/**
 * KevVPN - Blocking VPNs and Proxies from Connecting
 *
 * Combines the three approaches the older plugins each did in isolation:
 *   CIDR_Blocker  - range blocking, but the match ran as a MySQL query on every
 *                   connect. Here the ranges live in RAM and the database only
 *                   stores results.
 *   Lrthrome      - large remote CIDR feeds, but it needed a separate Rust
 *                   daemon and the socket extension. Here the feeds are fetched
 *                   over HTTP straight into the plugin.
 *   ProxyKiller   - live reputation lookups plus a SQL cache and whitelist.
 *                   Kept, minus SteamWorks and the custom config parser.
 *
 * Storage: MySQL by default, SQLite fully supported. Driver is whatever the
 * "kevvpn" section of databases.cfg points at.
 */

#include <sourcemod>
#include <ripext>

#undef REQUIRE_PLUGIN
#tryinclude <sourcebanspp>
#define REQUIRE_PLUGIN

#pragma semicolon 1
#pragma newdecls required

#define PLUGIN_VERSION "1.1"

#define CIDR_BUCKETS 256
#define MAX_IP_LEN   24
#define MAX_URL_LEN  256

// Stored verdicts. UNKNOWN is never written, it only marks a miss.
#define VERDICT_UNKNOWN 0
#define VERDICT_CLEAN   1
#define VERDICT_BLOCKED 2

enum struct CacheEntry
{
	int expiry;
	int verdict;
	char source[24];    // CIDR, Manual, ProxyCheck, Blackbox
	char provider[64];  // ISP or hosting company, when a lookup told us
}

ConVar cv_Enable, cv_Action, cv_KickMsg, cv_BanMinutes, cv_UseCidr, cv_UseProxyCheck,
       cv_ProxyCheckKey, cv_UseIpApi, cv_UseBlackbox, cv_CacheTtl, cv_UpdateHours,
       cv_Verbose, cv_AdminImmunity, cv_ApiUnion;

// One row per command, kept beside the registrations so a missing one shows in review.
static const char g_sHelp[][] =
{
	"sm_kevvpn_check <#userid|name|ip>  - test against every layer; kicks a live player if detected",
	"sm_kevvpn_status                   - ranges loaded, cache size, database and layer state",
	"sm_kevvpn_alts <#userid|name|id>   - every address a player has connected from, with verdicts",
	"sm_kevvpn_whitelist <target> [why] - let a player or address through, by SteamID or IP",
	"sm_kevvpn_unwhitelist <target>     - remove a whitelist entry",
	"sm_kevvpn_list                     - list whitelist entries",
	"sm_kevvpn_addvpn <ip|cidr> [why]   - permanently block an address or range the feeds missed",
	"sm_kevvpn_delvpn <ip|cidr>         - remove a manual block",
	"sm_kevvpn_vpnlist                  - list manual blocks",
	"sm_kevvpn_allowdc <provider> [why] - allow a hosting provider by name, e.g. NVIDIA for GeForce Now",
	"sm_kevvpn_denydc <provider>        - stop allowing a provider",
	"sm_kevvpn_dclist                   - list allowed providers",
	"sm_kevvpn_reload                   - re-read whitelist/blocklist/providers after editing the tables in SQL",
	"sm_kevvpn_update [clean]           - re-download blocklists; 'clean' deletes the old files first"
};

// Ranges bucketed by first octet: a /24 lands in one bucket, a /7 in two. Turns a
// 200k-entry scan into a few hundred compares without needing a trie.
ArrayList g_hCidr[CIDR_BUCKETS];
int g_iCidrCount;

// Manually confirmed ranges from kevvpn_blocklist. Checked before the feeds (an admin who
// confirmed a range outranks a third-party list), survives a feed reload, and logs as
// manual. Always tiny. Blocksize 2: [0] = network, [1] = mask.
ArrayList g_hManual;

// Provider names an admin accepts, matched case-insensitively as a substring of whatever
// the lookup reports. How 'let GeForce Now in' works without chasing NVIDIA's ranges.
ArrayList g_hProviders;

// Range matched, but hold the verdict until a lookup names the company behind it.
char g_sPendingSource[MAXPLAYERS + 1][24];

Database g_hDb;
bool g_bSqlite;
bool g_bDbReady;

StringMap g_hCache;      // L1: ip -> CacheEntry, avoids a query per connect
ArrayList g_hWhitelist;  // mirror of kevvpn_whitelist, so the check stays sync

int g_iPendingDownloads;
bool g_bExtReady;
bool g_bBooted; // first OnConfigsExecuted done; guards against per-map repeats

// Per-slot lookup state. Callbacks re-validate the userid, so a recycled slot can't inherit a verdict.
int  g_iCheckUserId[MAXPLAYERS + 1];
char g_sCheckIp[MAXPLAYERS + 1][MAX_IP_LEN];
// Best provider name so far. proxycheck names companies, blackbox doesn't, so don't blank a good answer.
char g_sCheckProvider[MAXPLAYERS + 1][64];

public Plugin myinfo =
{
	name = "KevVPN",
	author = "Kevin, RumbleFrog, Sikari",
	description = "Blocking VPNs and Proxies from Connecting",
	version = PLUGIN_VERSION,
	url = "https://steamcommunity.com/id/iamarealplayer/"
};

public void OnPluginStart()
{
	cv_Enable = CreateConVar("kevvpn_enable", "1", "Master switch.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	cv_Action = CreateConVar("kevvpn_action", "1", "Action on a detected VPN/proxy: 0 = log only, 1 = kick, 2 = SourceMod ban, 3 = SourceBans++ ban with a SourceMod fallback.", FCVAR_NOTIFY, true, 0.0, true, 3.0);
	cv_KickMsg = CreateConVar("kevvpn_kick_message", "VPN Detected", "Reason shown to the client, and recorded as the ban reason for actions 2 and 3.", FCVAR_NOTIFY);
	cv_BanMinutes = CreateConVar("kevvpn_ban_minutes", "0", "Ban length in minutes for actions 2 and 3. 0 is permanent.", FCVAR_NOTIFY, true, 0.0);
	cv_UseCidr = CreateConVar("kevvpn_use_cidr", "1", "Check the downloaded CIDR blocklists. Free and instant, no API budget.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	cv_UseProxyCheck = CreateConVar("kevvpn_use_proxycheck", "1", "Query proxycheck.io for addresses nothing else resolved.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	cv_ProxyCheckKey = CreateConVar("kevvpn_proxycheck_key", "", "proxycheck.io API key. Empty still works but the free anonymous tier is only 100 queries a day.", FCVAR_PROTECTED);
	cv_UseIpApi = CreateConVar("kevvpn_use_ipapi", "1", "Use ip-api.com when proxycheck.io gives no answer. Free, no key, and the only free source of a hosting/datacenter flag now that no plain CIDR feed publishes one.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	cv_UseBlackbox = CreateConVar("kevvpn_use_blackbox", "1", "Use blackbox.ipinfo.app as a last resort. It answers yes/no only, with no provider name.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	cv_CacheTtl = CreateConVar("kevvpn_cache_hours", "168", "Hours a stored verdict stays valid before the address is re-checked.", FCVAR_NOTIFY, true, 1.0, true, 8760.0);
	cv_UpdateHours = CreateConVar("kevvpn_update_hours", "24", "Hours between blocklist re-downloads. 0 disables automatic updates.", FCVAR_NOTIFY, true, 0.0, true, 168.0);
	cv_Verbose = CreateConVar("kevvpn_log_clean", "0", "Also log addresses that passed every check. Noisy; for tuning only.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	cv_ApiUnion = CreateConVar("kevvpn_api_union", "1", "Keep asking the remaining services after one says clean, and block if ANY of them flags the address. Catches rented RDP/VPS boxes that proxycheck.io calls clean but ip-api reports as hosting. 0 = stop at the first definitive answer, which is cheaper but misses those.", FCVAR_NOTIFY, true, 0.0, true, 1.0);
	cv_AdminImmunity = CreateConVar("kevvpn_admin_immunity", "0", "Let admins skip every KevVPN check. 0 = nobody is exempt for being an admin, including ROOT, and the whitelist is the only way through. 1 = ROOT, or anyone granted the kevvpn_immunity override, is exempt.", FCVAR_NOTIFY, true, 0.0, true, 1.0);

	// Exemption marker, only consulted while kevvpn_admin_immunity is 1. Lets immunity go to
	// a non-root group via admin_overrides.cfg instead of to every admin.
	RegAdminCmd("kevvpn_immunity", Command_Dummy, ADMFLAG_ROOT, "Exemption from every KevVPN check. Ignored entirely unless kevvpn_admin_immunity is 1.");

	// Admin-only: nothing here for a regular player to act on.
	RegAdminCmd("sm_kevvpn", Command_Help, ADMFLAG_ROOT, "List every KevVPN command.");
	RegAdminCmd("sm_helpvpn", Command_Help, ADMFLAG_ROOT, "List every KevVPN command. (alias)");
	RegAdminCmd("sm_helpkevvpn", Command_Help, ADMFLAG_ROOT, "List every KevVPN command. (alias)");

	RegAdminCmd("sm_kevvpn_whitelist", Command_Whitelist, ADMFLAG_ROOT, "Allow a player or address through. Usage: sm_kevvpn_whitelist <#userid|name|STEAM_1:0:X|1.2.3.4> [comment]");
	RegAdminCmd("sm_kevvpn_unwhitelist", Command_Unwhitelist, ADMFLAG_ROOT, "Remove a whitelist entry. Usage: sm_kevvpn_unwhitelist <#userid|name|STEAM_1:0:X|1.2.3.4>");
	RegAdminCmd("sm_kevvpn_list", Command_List, ADMFLAG_ROOT, "List every KevVPN whitelist entry.");
	RegAdminCmd("sm_kevvpn_alts", Command_Alts, ADMFLAG_ROOT, "Every address a player has connected from, with its verdict. Usage: sm_kevvpn_alts <#userid|name|STEAM_1:0:X>");
	RegAdminCmd("sm_kevvpn_addvpn", Command_AddVpn, ADMFLAG_ROOT, "Permanently block an address or range the feeds missed. Usage: sm_kevvpn_addvpn <1.2.3.4|1.2.3.0/24> [comment]");
	RegAdminCmd("sm_kevvpn_delvpn", Command_DelVpn, ADMFLAG_ROOT, "Remove a manual block entry. Usage: sm_kevvpn_delvpn <1.2.3.4|1.2.3.0/24>");
	RegAdminCmd("sm_kevvpn_vpnlist", Command_VpnList, ADMFLAG_ROOT, "List every manually blocked address or range.");
	RegAdminCmd("sm_kevvpn_allowdc", Command_AllowDc, ADMFLAG_ROOT, "Allow a hosting provider through by name, e.g. sm_kevvpn_allowdc NVIDIA. Matched as a substring of the reported provider.");
	RegAdminCmd("sm_kevvpn_denydc", Command_DenyDc, ADMFLAG_ROOT, "Stop allowing a provider. Usage: sm_kevvpn_denydc <name>");
	RegAdminCmd("sm_kevvpn_dclist", Command_DcList, ADMFLAG_ROOT, "List every allowed hosting provider.");
	RegAdminCmd("sm_kevvpn_update", Command_Update, ADMFLAG_ROOT, "Re-download the blocklists now. Usage: sm_kevvpn_update [clean] - 'clean' deletes the existing files first, which is required after removing a URL from sources.ini.");
	RegAdminCmd("sm_kevvpn_reload", Command_Reload, ADMFLAG_ROOT, "Re-read the whitelist, manual blocklist and provider allowlist from the database. Needed after editing those tables directly with SQL.");
	RegAdminCmd("sm_kevvpn_check", Command_Check, ADMFLAG_ROOT, "Test an address or player against every layer without punishing. Usage: sm_kevvpn_check <#userid|name|1.2.3.4>");
	RegAdminCmd("sm_kevvpn_status", Command_Status, ADMFLAG_ROOT, "Show range count, cache size, database and layer state.");

	for (int i = 0; i < CIDR_BUCKETS; i++)
		g_hCidr[i] = new ArrayList(2); // [0] = network, [1] = mask

	g_hCache = new StringMap();
	g_hWhitelist = new ArrayList(ByteCountToCells(64));
	g_hManual = new ArrayList(2);
	g_hProviders = new ArrayList(ByteCountToCells(64));

	EnsureDirs();
	AutoExecConfig(true, "KevVPN");
}

public void OnConfigsExecuted()
{
	g_bExtReady = (GetFeatureStatus(FeatureType_Native, "HTTPRequest.HTTPRequest") == FeatureStatus_Available);
	if (!g_bExtReady)
		LogError("[KevVPN] REST in Pawn is not loaded. Blocklists cannot be downloaded and the API layers are disabled; only already-downloaded ranges will be used.");

	// proxycheck.io answers anonymous requests from some origins and refuses others, so a keyless
	// setup can silently contribute nothing. The chain still falls through, but say so once.
	if (cv_UseProxyCheck.BoolValue)
	{
		char sKey[64];
		cv_ProxyCheckKey.GetString(sKey, sizeof(sKey));
		if (!sKey[0])
			LogMessage("[KevVPN] No proxycheck.io key set. Anonymous requests are rate limited and may be refused entirely; a free key at proxycheck.io/dashboard raises this to 1000 lookups a day. ip-api and blackbox still cover the gap.");
	}

	if (g_hDb == null)
		ConnectDatabase();

	// OnConfigsExecuted fires on EVERY map change. Doing the rest per map re-parsed millions of
	// ranges mid-load and stacked a fresh update timer each time.
	if (g_bBooted)
		return;
	g_bBooted = true;

	LoadAllLists();

	// One-shot on boot, then on the interval. A fresh install has no lists at all, so the first fetch matters.
	CreateTimer(30.0, Timer_Update, _, TIMER_FLAG_NO_MAPCHANGE);
	if (cv_UpdateHours.IntValue > 0)
		CreateTimer(float(cv_UpdateHours.IntValue) * 3600.0, Timer_Update, _, TIMER_REPEAT);
}

public Action Command_Dummy(int client, int args) { return Plugin_Handled; }

// With kevvpn_admin_immunity 0 (default) nobody is exempt by admin status; the whitelist is
// the only way through. Deliberately does not call CheckCommandAccess there: a ROOT admin
// satisfies every flag by definition, so it returns true whatever is passed, including an
// override they were never granted. No flag-based way to exclude root, so don't ask.
bool IsExempt(int client)
{
	if (!cv_AdminImmunity.BoolValue)
		return false;

	return CheckCommandAccess(client, "kevvpn_immunity", ADMFLAG_ROOT, false);
}

public Action Command_Help(int client, int args)
{
	// The list is long, so it goes to console and chat just points at it.
	if (client > 0)
		PrintToChat(client, "\x02[KevVPN]\x01 Command list printed to your console (press \x02~\x01).");

	AltsReply(client, "[KevVPN] !kevvpn / !helpvpn / !helpkevvpn shows this list (ROOT-ONLY)");

	for (int i = 0; i < sizeof(g_sHelp); i++)
		AltsReply(client, "  %s", g_sHelp[i]);

	return Plugin_Handled;
}

// CreateDirectory does not create parents, so every level is made explicitly.
void EnsureDirs()
{
	char sPath[PLATFORM_MAX_PATH];

	BuildPath(Path_SM, sPath, sizeof(sPath), "configs/kevvpn");
	if (!DirExists(sPath))
		CreateDirectory(sPath, 511);

	BuildPath(Path_SM, sPath, sizeof(sPath), "data/kevvpn");
	if (!DirExists(sPath))
		CreateDirectory(sPath, 511);

	BuildPath(Path_SM, sPath, sizeof(sPath), "data/kevvpn/lists");
	if (!DirExists(sPath))
		CreateDirectory(sPath, 511);
}

// ---- Database -------------------------------------------------------------

void ConnectDatabase()
{
	if (SQL_CheckConfig("kevvpn"))
		Database.Connect(OnDbConnected, "kevvpn");
	else
		Database.Connect(OnDbConnected, "default");
}

public void OnDbConnected(Database db, const char[] error, any data)
{
	if (db == null)
	{
		LogError("[KevVPN] Database connection failed, enforcement is suspended until it recovers: %s", error);
		return;
	}

	g_hDb = db;

	char sDriver[16];
	g_hDb.Driver.GetIdentifier(sDriver, sizeof(sDriver));
	g_bSqlite = StrEqual(sDriver, "sqlite", false);
	if (!g_bSqlite)
		g_hDb.SetCharset("utf8mb4");

	// Natural primary keys throughout, so no AUTO_INCREMENT divergence between drivers.
	// INTEGER and VARCHAR mean the same thing on both.
	g_hDb.Query(SqlCallback_Schema,
		"CREATE TABLE IF NOT EXISTS kevvpn_ips ( \
		ip VARCHAR(45) NOT NULL PRIMARY KEY, \
		verdict INTEGER NOT NULL DEFAULT 0, \
		source VARCHAR(32) NOT NULL DEFAULT '', \
		provider VARCHAR(64) NOT NULL DEFAULT '', \
		checked INTEGER NOT NULL DEFAULT 0)");

	g_hDb.Query(SqlCallback_Schema,
		"CREATE TABLE IF NOT EXISTS kevvpn_players ( \
		steamid VARCHAR(32) NOT NULL, \
		ip VARCHAR(45) NOT NULL, \
		name VARCHAR(64) NOT NULL DEFAULT '', \
		first_seen INTEGER NOT NULL DEFAULT 0, \
		last_seen INTEGER NOT NULL DEFAULT 0, \
		PRIMARY KEY (steamid, ip))");

	g_hDb.Query(SqlCallback_Schema,
		"CREATE TABLE IF NOT EXISTS kevvpn_whitelist ( \
		identity VARCHAR(45) NOT NULL PRIMARY KEY, \
		added_by VARCHAR(32) NOT NULL DEFAULT '', \
		comment VARCHAR(128) NOT NULL DEFAULT '', \
		added INTEGER NOT NULL DEFAULT 0)");

	g_hDb.Query(SqlCallback_Schema,
		"CREATE TABLE IF NOT EXISTS kevvpn_blocklist ( \
		cidr VARCHAR(45) NOT NULL PRIMARY KEY, \
		added_by VARCHAR(32) NOT NULL DEFAULT '', \
		comment VARCHAR(128) NOT NULL DEFAULT '', \
		added INTEGER NOT NULL DEFAULT 0)");

	g_hDb.Query(SqlCallback_Schema,
		"CREATE TABLE IF NOT EXISTS kevvpn_providers ( \
		name VARCHAR(64) NOT NULL PRIMARY KEY, \
		added_by VARCHAR(32) NOT NULL DEFAULT '', \
		comment VARCHAR(128) NOT NULL DEFAULT '', \
		added INTEGER NOT NULL DEFAULT 0)");

	// For a table created before the provider column existed; a duplicate-column error is expected.
	g_hDb.Query(SqlCallback_Silent2,
		"ALTER TABLE kevvpn_ips ADD COLUMN provider VARCHAR(64) NOT NULL DEFAULT ''");

	g_bDbReady = true;
	LogMessage("[KevVPN] Database connected (%s).", g_bSqlite ? "sqlite" : "mysql");
	LoadWhitelist();
	LoadManualBlocklist();
	LoadProviders();
}

public void SqlCallback_Schema(Database db, DBResultSet results, const char[] error, any data)
{
	if (results == null)
	{
		g_bDbReady = false;
		LogError("[KevVPN] Table creation failed, enforcement suspended: %s", error);
	}
}

public void SqlCallback_Silent(Database db, DBResultSet results, const char[] error, any data)
{
	if (results == null)
		LogError("[KevVPN] Query failed: %s", error);
}

// Best-effort schema migration; a failure here is expected and harmless.
public void SqlCallback_Silent2(Database db, DBResultSet results, const char[] error, any data)
{
}

// ---- Client entry point ---------------------------------------------------

public void OnClientPostAdminCheck(int client)
{
	g_iCheckUserId[client] = 0;
	g_sCheckIp[client][0] = '\0';
	g_sCheckProvider[client][0] = '\0';

	if (!cv_Enable.BoolValue || IsFakeClient(client) || IsClientSourceTV(client))
		return;

	if (IsExempt(client))
		return;

	char sIp[MAX_IP_LEN];
	if (!GetClientIP(client, sIp, sizeof(sIp), true))
		return;

	// Recorded for every connect whatever the verdict; feeds sm_kevvpn_alts, so it precedes any early return.
	RecordConnection(client, sIp);

	if (IsWhitelisted(client, sIp))
		return;

	g_sPendingSource[client][0] = '\0';

	// Layer 0: hand-confirmed ranges. Outranks the provider allowlist, the admin already saw the case.
	char sRange[40];
	if (FindManualMatch(sIp, sRange, sizeof(sRange)))
	{
		StoreVerdict(sIp, VERDICT_BLOCKED, "Manual", "");
		Punish(client, sIp, "Manual", sRange);
		return;
	}

	// Layer 1: downloaded ranges. No network call, resolves most datacenter traffic before spending API budget.
	if (cv_UseCidr.BoolValue && FindCidrMatch(sIp, sRange, sizeof(sRange)))
	{
		// Fast path: with no provider allowlist there is nothing to look up.
		if (g_hProviders.Length == 0)
		{
			StoreVerdict(sIp, VERDICT_BLOCKED, "CIDR", "");
			Punish(client, sIp, "CIDR", sRange);
			return;
		}
		// Otherwise hold the verdict until something names the company, so GeForce Now isn't blocked by its range.
		strcopy(g_sPendingSource[client], sizeof(g_sPendingSource[]), "CIDR");
	}

	// Layer 2: a verdict we already paid for, in RAM.
	CacheEntry entry;
	if (CacheGet(sIp, entry))
	{
		ResolveVerdict(client, sIp,
			entry.verdict == VERDICT_BLOCKED, entry.source, entry.provider, false);
		return;
	}

	g_iCheckUserId[client] = GetClientUserId(client);
	strcopy(g_sCheckIp[client], MAX_IP_LEN, sIp);
	g_sCheckProvider[client][0] = '\0';

	// Layer 3: a verdict another session, or the other server, already paid for.
	if (g_bDbReady)
	{
		char sEsc[64], sQuery[256];
		g_hDb.Escape(sIp, sEsc, sizeof(sEsc));
		FormatEx(sQuery, sizeof(sQuery),
			"SELECT verdict, source, provider FROM kevvpn_ips WHERE ip = '%s' AND checked > %d LIMIT 1",
			sEsc, GetTime() - cv_CacheTtl.IntValue * 3600);
		g_hDb.Query(SqlCallback_IpLookup, sQuery, GetClientUserId(client));
		return;
	}

	BeginApiCheck(client, sIp);
}

public void SqlCallback_IpLookup(Database db, DBResultSet results, const char[] error, any userid)
{
	int client = ResolvePending(userid);
	if (client < 1)
		return;

	char sIp[MAX_IP_LEN];
	strcopy(sIp, sizeof(sIp), g_sCheckIp[client]);

	if (results != null && results.FetchRow())
	{
		int verdict = results.FetchInt(0);
		char sSource[24], sProvider[64];
		results.FetchString(1, sSource, sizeof(sSource));
		results.FetchString(2, sProvider, sizeof(sProvider));

		CacheSet(sIp, verdict, sSource, sProvider); // promote into L1
		g_iCheckUserId[client] = 0;
		ResolveVerdict(client, sIp, verdict == VERDICT_BLOCKED, sSource, sProvider, false);
		return;
	}

	BeginApiCheck(client, sIp);
}

public void OnClientDisconnect(int client)
{
	g_iCheckUserId[client] = 0;
	g_sCheckIp[client][0] = '\0';
	g_sCheckProvider[client][0] = '\0';
	g_sPendingSource[client][0] = '\0';
}

// Upsert on (steamid, ip) so the pair is stored once with a moving last_seen. Rows are NEVER
// deleted: this is the permanent address history behind sm_kevvpn_alts. Only kevvpn_ips
// carries a TTL, and that governs re-checking, not retention.
void RecordConnection(int client, const char[] sIp)
{
	if (!g_bDbReady)
		return;

	char sAuth[32];
	if (!GetClientAuthId(client, AuthId_Steam2, sAuth, sizeof(sAuth)))
		return;

	char sName[MAX_NAME_LENGTH], sNameEsc[MAX_NAME_LENGTH * 2 + 1], sIpEsc[64], sAuthEsc[64];
	GetClientName(client, sName, sizeof(sName));
	g_hDb.Escape(sName, sNameEsc, sizeof(sNameEsc));
	g_hDb.Escape(sIp, sIpEsc, sizeof(sIpEsc));
	g_hDb.Escape(sAuth, sAuthEsc, sizeof(sAuthEsc));

	int now = GetTime();
	char sQuery[512];

	if (g_bSqlite)
	{
		FormatEx(sQuery, sizeof(sQuery),
			"INSERT OR IGNORE INTO kevvpn_players (steamid, ip, name, first_seen, last_seen) VALUES ('%s', '%s', '%s', %d, %d)",
			sAuthEsc, sIpEsc, sNameEsc, now, now);
		g_hDb.Query(SqlCallback_Silent, sQuery);

		FormatEx(sQuery, sizeof(sQuery),
			"UPDATE kevvpn_players SET name = '%s', last_seen = %d WHERE steamid = '%s' AND ip = '%s'",
			sNameEsc, now, sAuthEsc, sIpEsc);
		g_hDb.Query(SqlCallback_Silent, sQuery);
		return;
	}

	FormatEx(sQuery, sizeof(sQuery),
		"INSERT INTO kevvpn_players (steamid, ip, name, first_seen, last_seen) VALUES ('%s', '%s', '%s', %d, %d) \
		ON DUPLICATE KEY UPDATE name = VALUES(name), last_seen = VALUES(last_seen)",
		sAuthEsc, sIpEsc, sNameEsc, now, now);
	g_hDb.Query(SqlCallback_Silent, sQuery);
}

void StoreVerdict(const char[] sIp, int verdict, const char[] sSource, const char[] sProvider)
{
	CacheSet(sIp, verdict, sSource, sProvider);

	if (!g_bDbReady)
		return;

	char sIpEsc[64], sSrcEsc[64], sProvEsc[160], sQuery[640];
	g_hDb.Escape(sIp, sIpEsc, sizeof(sIpEsc));
	g_hDb.Escape(sSource, sSrcEsc, sizeof(sSrcEsc));
	g_hDb.Escape(sProvider, sProvEsc, sizeof(sProvEsc));
	int now = GetTime();

	if (g_bSqlite)
	{
		FormatEx(sQuery, sizeof(sQuery),
			"INSERT OR REPLACE INTO kevvpn_ips (ip, verdict, source, provider, checked) VALUES ('%s', %d, '%s', '%s', %d)",
			sIpEsc, verdict, sSrcEsc, sProvEsc, now);
	}
	else
	{
		FormatEx(sQuery, sizeof(sQuery),
			"INSERT INTO kevvpn_ips (ip, verdict, source, provider, checked) VALUES ('%s', %d, '%s', '%s', %d) \
			ON DUPLICATE KEY UPDATE verdict = VALUES(verdict), source = VALUES(source), provider = VALUES(provider), checked = VALUES(checked)",
			sIpEsc, verdict, sSrcEsc, sProvEsc, now);
	}
	g_hDb.Query(SqlCallback_Silent, sQuery);
}

// Single funnel for every layer, so the provider allowlist is applied exactly once.
void ResolveVerdict(int client, const char[] sIp, bool bBlocked, const char[] sSource,
                    const char[] sProvider, bool bStore)
{
	g_iCheckUserId[client] = 0;

	// A range hit that was held pending a provider lookup still counts as a hit.
	char sFinalSource[24];
	strcopy(sFinalSource, sizeof(sFinalSource), sSource);
	if (g_sPendingSource[client][0] != '\0')
	{
		bBlocked = true;
		if (!sFinalSource[0] || StrEqual(sFinalSource, "ProxyCheck") || StrEqual(sFinalSource, "Blackbox"))
			strcopy(sFinalSource, sizeof(sFinalSource), g_sPendingSource[client]);
		g_sPendingSource[client][0] = '\0';
	}

	if (bStore)
		StoreVerdict(sIp, bBlocked ? VERDICT_BLOCKED : VERDICT_CLEAN, sFinalSource, sProvider);

	if (!bBlocked)
	{
		if (cv_Verbose.BoolValue)
			LogMessage("[KevVPN] %N (%s) passed: %s.", client, sIp, sFinalSource[0] ? sFinalSource : "no match");
		return;
	}

	// Provider allowlist is the last word: an admin naming a company overrides every feed calling it a datacenter.
	if (sProvider[0] && IsProviderAllowed(sProvider))
	{
		LogToFile("addons/sourcemod/logs/KevVPN.log",
			"[KevVPN] %N (%s) allowed: %s matched %s but the provider is on the allowlist.",
			client, sIp, sFinalSource, sProvider);
		return;
	}

	char sDetail[96];
	if (sProvider[0])
		FormatEx(sDetail, sizeof(sDetail), "(%s)", sProvider);
	else
		strcopy(sDetail, sizeof(sDetail), "(provider unknown)");

	Punish(client, sIp, sFinalSource, sDetail);
}

bool IsProviderAllowed(const char[] sProvider)
{
	char sEntry[64];
	for (int i = 0; i < g_hProviders.Length; i++)
	{
		g_hProviders.GetString(i, sEntry, sizeof(sEntry));
		if (sEntry[0] && StrContains(sProvider, sEntry, false) != -1)
			return true;
	}
	return false;
}

void Punish(int client, const char[] sIp, const char[] sSource, const char[] sDetail)
{
	char sName[MAX_NAME_LENGTH], sAuth[32];
	GetClientName(client, sName, sizeof(sName));
	if (!GetClientAuthId(client, AuthId_Steam2, sAuth, sizeof(sAuth)))
		strcopy(sAuth, sizeof(sAuth), "UNKNOWN");

	int iAction = cv_Action.IntValue;

	// An unreachable database means the whitelist never loaded. Punishing then kicks the exact people exempted.
	if (!g_bDbReady && iAction > 0)
	{
		LogToFile("addons/sourcemod/logs/KevVPN.log",
			"[KevVPN] %s (%s) %s | SUPPRESSED (database down, whitelist unknown) | %s: %s",
			sName, sAuth, sIp, sSource, sDetail);
		return;
	}

	static const char sActionNames[][] = { "detected (log only)", "KICKED", "BANNED (SourceMod)", "BANNED (SourceBans++)" };
	LogToFile("addons/sourcemod/logs/KevVPN.log", "[KevVPN] %s (%s) %s | %s | %s: %s",
		sName, sAuth, sIp, sActionNames[iAction], sSource, sDetail);

	if (iAction <= 0)
		return;

	char sMsg[192];
	cv_KickMsg.GetString(sMsg, sizeof(sMsg));
	int iMinutes = cv_BanMinutes.IntValue;

	switch (iAction)
	{
		case 1:
		{
			KickClient(client, "%s", sMsg);
		}
		case 2:
		{
			BanClient(client, iMinutes, BANFLAG_AUTO, sMsg, sMsg, "KevVPN");
		}
		case 3:
		{
			// SourceBans++ is optional; falling back keeps the ban enforceable instead of erroring and leaving them on.
			if (GetFeatureStatus(FeatureType_Native, "SBPP_BanPlayer") == FeatureStatus_Available)
			{
				SBPP_BanPlayer(0, client, iMinutes, sMsg);
			}
			else
			{
				LogMessage("[KevVPN] SourceBans++ is not loaded; using the SourceMod ban for %s.", sName);
				BanClient(client, iMinutes, BANFLAG_AUTO, sMsg, sMsg, "KevVPN");
			}
		}
	}
}

// ---- Reputation APIs ------------------------------------------------------

void BeginApiCheck(int client, const char[] sIp)
{
	if (!g_bExtReady)
	{
		LogError("[KevVPN] %s reached the API layer but REST in Pawn is not loaded; not checked.", sIp);
		g_iCheckUserId[client] = 0;
		return;
	}

	if (!cv_UseProxyCheck.BoolValue && !cv_UseIpApi.BoolValue && !cv_UseBlackbox.BoolValue)
	{
		LogError("[KevVPN] %s reached the API layer but every service is disabled; not checked.", sIp);
		g_iCheckUserId[client] = 0;
		return;
	}

	LogMessage("[KevVPN] Checking %s against the reputation services.", sIp);

	if (cv_UseProxyCheck.BoolValue)
	{
		QueryProxyCheck(client, sIp);
		return;
	}
	if (cv_UseIpApi.BoolValue)
	{
		QueryIpApi(client, sIp);
		return;
	}
	if (cv_UseBlackbox.BoolValue)
	{
		QueryBlackbox(client, sIp);
		return;
	}
	g_iCheckUserId[client] = 0;
}

// ip-api.com: free, keyless, 45 req/min. Free tier is HTTP only, so this URL must not be https.
// Its hosting flag is the datacenter signal no free CIDR feed publishes any more, which
// makes it the layer that catches GeForce Now, ExitLag and similar.
void QueryIpApi(int client, const char[] sIp)
{
	char sUrl[MAX_URL_LEN];
	FormatEx(sUrl, sizeof(sUrl),
		"http://ip-api.com/json/%s?fields=status,proxy,hosting,mobile,isp,org", sIp);

	HTTPRequest request = new HTTPRequest(sUrl);
	request.Get(OnIpApiDone, GetClientUserId(client));
}

public void OnIpApiDone(HTTPResponse response, any userid, const char[] error)
{
	int client = ResolvePending(userid);
	if (client < 1)
		return;

	char sIp[MAX_IP_LEN];
	strcopy(sIp, sizeof(sIp), g_sCheckIp[client]);

	if (error[0] == '\0' && response.Status == HTTPStatus_OK && response.Data != null)
	{
		JSONObject root = view_as<JSONObject>(response.Data);

		char sStatus[16];
		root.GetString("status", sStatus, sizeof(sStatus));

		if (StrEqual(sStatus, "success", false))
		{
			bool bProxy   = root.HasKey("proxy")   && root.GetBool("proxy");
			bool bHosting = root.HasKey("hosting") && root.GetBool("hosting");
			bool bMobile  = root.HasKey("mobile")  && root.GetBool("mobile");

			// org is the hosting company, isp the carrier. Prefer org.
			char sProvider[64];
			if (!root.GetString("org", sProvider, sizeof(sProvider)) || !sProvider[0])
				root.GetString("isp", sProvider, sizeof(sProvider));

			// mobile is recorded but never acted on: a cellular address proves nothing and blocking it hits every 5G player.
			if (bMobile && cv_Verbose.BoolValue)
				LogMessage("[KevVPN] %s is a mobile/cellular address (%s).", sIp, sProvider);

			RememberProvider(client, sProvider);
			bool bBlocked = (bProxy || bHosting);

			if (!bBlocked && cv_ApiUnion.BoolValue && cv_UseBlackbox.BoolValue)
			{
				QueryBlackbox(client, sIp);
				return;
			}

			FinishCheck(client, sIp, bBlocked, "IPAPI", g_sCheckProvider[client]);
			return;
		}
	}
	else if (error[0] != '\0')
	{
		LogMessage("[KevVPN] ip-api.com request failed for %s: %s", sIp, error);
	}

	if (cv_UseBlackbox.BoolValue)
	{
		QueryBlackbox(client, sIp);
		return;
	}
	FinishCheck(client, sIp, false, "no service answered", "");
}

// proxycheck.io returns JSON: {"status":"ok","1.2.3.4":{"proxy":"yes",...}}
void QueryProxyCheck(int client, const char[] sIp)
{
	char sUrl[MAX_URL_LEN], sKey[64];
	cv_ProxyCheckKey.GetString(sKey, sizeof(sKey));

	// vpn=1 reports VPN ranges, not just open proxies. asn=1 adds provider and ISP names free, which the allowlist matches.
	if (sKey[0])
		FormatEx(sUrl, sizeof(sUrl), "https://proxycheck.io/v2/%s?vpn=1&asn=1&key=%s", sIp, sKey);
	else
		FormatEx(sUrl, sizeof(sUrl), "https://proxycheck.io/v2/%s?vpn=1&asn=1", sIp);

	HTTPRequest request = new HTTPRequest(sUrl);
	request.Get(OnProxyCheckDone, GetClientUserId(client));
}

public void OnProxyCheckDone(HTTPResponse response, any userid, const char[] error)
{
	int client = ResolvePending(userid);
	if (client < 1)
		return;

	char sIp[MAX_IP_LEN];
	strcopy(sIp, sizeof(sIp), g_sCheckIp[client]);

	if (response.Status != HTTPStatus_OK)
		LogMessage("[KevVPN] proxycheck.io returned HTTP %d for %s (a 403 here usually means the key is missing or rejected). Falling back.",
			view_as<int>(response.Status), sIp);

	bool bUsable = (error[0] == '\0' && response.Status == HTTPStatus_OK && response.Data != null);
	if (bUsable)
	{
		JSONObject root = view_as<JSONObject>(response.Data);

		char sStatus[16];
		root.GetString("status", sStatus, sizeof(sStatus));

		// denied means out of quota or a bad key. Treat as no answer, not clean, or an exhausted key lets everyone in.
		if (StrEqual(sStatus, "ok", false) && root.HasKey(sIp))
		{
			JSONObject node = view_as<JSONObject>(root.Get(sIp));
			if (node != null)
			{
				char sProxy[8], sProvider[64];
				bool bGot = node.GetString("proxy", sProxy, sizeof(sProxy));

				// provider is the hosting company; isp is the fallback for a residential address.
				if (!node.GetString("provider", sProvider, sizeof(sProvider)) || !sProvider[0])
					node.GetString("isp", sProvider, sizeof(sProvider));

				delete node;

				if (bGot)
				{
					bool bBlocked = StrEqual(sProxy, "yes", false);
					RememberProvider(client, sProvider);

					// A clean answer from one service isn't proof: a rented RDP or VPS is not a proxy, so
					// proxycheck can honestly call it clean while ip-api reports hosting. Keep asking.
					if (!bBlocked && cv_ApiUnion.BoolValue && cv_UseIpApi.BoolValue)
					{
						QueryIpApi(client, sIp);
						return;
					}

					FinishCheck(client, sIp, bBlocked, "ProxyCheck", g_sCheckProvider[client]);
					return;
				}
			}
		}
		else if (!StrEqual(sStatus, "ok", false))
		{
			LogMessage("[KevVPN] proxycheck.io returned status '%s' for %s. Falling back.", sStatus, sIp);
		}
	}
	else if (error[0] != '\0')
	{
		LogMessage("[KevVPN] proxycheck.io request failed for %s: %s", sIp, error);
	}

	if (cv_UseIpApi.BoolValue)
	{
		QueryIpApi(client, sIp);
		return;
	}
	if (cv_UseBlackbox.BoolValue)
	{
		QueryBlackbox(client, sIp);
		return;
	}
	FinishCheck(client, sIp, false, "no service answered", "");
}

// blackbox.ipinfo.app answers a bare Y or N, not JSON, so download the body instead of using .Data.
void QueryBlackbox(int client, const char[] sIp)
{
	char sUrl[MAX_URL_LEN], sPath[PLATFORM_MAX_PATH];
	FormatEx(sUrl, sizeof(sUrl), "https://blackbox.ipinfo.app/lookup/%s", sIp);
	BuildPath(Path_SM, sPath, sizeof(sPath), "data/kevvpn/bb_%d.txt", GetClientUserId(client));

	HTTPRequest request = new HTTPRequest(sUrl);
	request.DownloadFile(sPath, OnBlackboxDone, GetClientUserId(client));
}

public void OnBlackboxDone(HTTPStatus status, any userid, const char[] error)
{
	char sPath[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, sPath, sizeof(sPath), "data/kevvpn/bb_%d.txt", userid);

	int client = ResolvePending(userid);
	if (client < 1)
	{
		DeleteFile(sPath);
		return;
	}

	char sIp[MAX_IP_LEN];
	strcopy(sIp, sizeof(sIp), g_sCheckIp[client]);

	bool bBlocked = false, bAnswered = false;

	if (error[0] == '\0' && status == HTTPStatus_OK)
	{
		File hFile = OpenFile(sPath, "r");
		if (hFile != null)
		{
			char sBody[16];
			if (hFile.ReadLine(sBody, sizeof(sBody)))
			{
				TrimString(sBody);
				if (sBody[0] == 'Y' || sBody[0] == 'y')
				{
					bBlocked = true;
					bAnswered = true;
				}
				else if (sBody[0] == 'N' || sBody[0] == 'n')
				{
					bAnswered = true;
				}
			}
			hFile.Close();
		}
	}
	else if (error[0] != '\0')
	{
		LogMessage("[KevVPN] blackbox.ipinfo.app request failed for %s: %s", sIp, error);
	}

	DeleteFile(sPath);

	if (!bAnswered)
	{
		FinishCheck(client, sIp, false, "no service answered", "");
		return;
	}
	// Blackbox never names a provider, so carry through whatever an earlier service reported.
	FinishCheck(client, sIp, bBlocked, "Blackbox", g_sCheckProvider[client]);
}

// Keeps the first non-empty provider seen during a lookup.
void RememberProvider(int client, const char[] sProvider)
{
	if (sProvider[0] && !g_sCheckProvider[client][0])
		strcopy(g_sCheckProvider[client], sizeof(g_sCheckProvider[]), sProvider);
}

// Resolves a pending lookup back to its client, rejecting a recycled slot.
int ResolvePending(int userid)
{
	int client = GetClientOfUserId(userid);
	if (client < 1 || client > MaxClients || !IsClientInGame(client))
		return -1;
	if (g_iCheckUserId[client] != userid)
		return -1;
	return client;
}

void FinishCheck(int client, const char[] sIp, bool bBlocked, const char[] sSource, const char[] sProvider)
{
	// Only store a real answer. Recording nobody-answered as clean gives a VPN a free pass for the whole TTL.
	bool bStore = !StrEqual(sSource, "no service answered");

	// Always logged, never gated behind kevvpn_log_clean. Every service failing means the API layer
	// is dead and everything the CIDR lists miss is let through unchecked. That must not be silent.
	if (!bStore)
		LogError("[KevVPN] No service answered for %s. proxycheck.io, ip-api and blackbox all failed or are disabled; this address was NOT checked.", sIp);
	else
		LogMessage("[KevVPN] %s answered for %s: %s%s%s", sSource, sIp,
			bBlocked ? "vpn/proxy" : "clean",
			sProvider[0] ? " | " : "", sProvider);

	ResolveVerdict(client, sIp, bBlocked, sSource, sProvider, bStore);
}

// ---- L1 cache -------------------------------------------------------------

bool CacheGet(const char[] sIp, CacheEntry entry)
{
	if (!g_hCache.GetArray(sIp, entry, sizeof(entry)))
		return false;

	if (entry.expiry <= GetTime())
	{
		g_hCache.Remove(sIp);
		return false;
	}
	return true;
}

void CacheSet(const char[] sIp, int verdict, const char[] sSource, const char[] sProvider)
{
	CacheEntry entry;
	entry.expiry = GetTime() + cv_CacheTtl.IntValue * 3600;
	entry.verdict = verdict;
	strcopy(entry.source, sizeof(entry.source), sSource);
	strcopy(entry.provider, sizeof(entry.provider), sProvider);
	g_hCache.SetArray(sIp, entry, sizeof(entry), true);
}

// ---- CIDR store -----------------------------------------------------------

void ClearCidr()
{
	for (int i = 0; i < CIDR_BUCKETS; i++)
		g_hCidr[i].Clear();
	g_iCidrCount = 0;
}

// A range is filed under every first octet it spans, so lookup only reads one bucket.
void AddCidr(int network, int mask)
{
	network &= mask;

	int lo = (network >>> 24) & 0xFF;
	int hi = ((network | ~mask) >>> 24) & 0xFF;

	for (int b = lo; b <= hi; b++)
	{
		g_hCidr[b].Push(network);
		g_hCidr[b].Set(g_hCidr[b].Length - 1, mask, 1);
	}
	g_iCidrCount++;
}

bool FindCidrMatch(const char[] sIp, char[] sOut, int iOutLen)
{
	int ip = IpToInt(sIp);
	if (ip == 0)
		return false;

	ArrayList list = g_hCidr[(ip >>> 24) & 0xFF];
	for (int i = 0; i < list.Length; i++)
	{
		int mask = list.Get(i, 1);
		if ((ip & mask) == list.Get(i, 0))
		{
			char sNet[MAX_IP_LEN];
			IntToIp(list.Get(i, 0), sNet, sizeof(sNet));
			FormatEx(sOut, iOutLen, "%s/%d", sNet, MaskToPrefix(mask));
			return true;
		}
	}
	return false;
}

// ---- Manual blocklist -----------------------------------------------------

void LoadManualBlocklist()
{
	if (!g_bDbReady)
		return;
	g_hDb.Query(SqlCallback_ManualList, "SELECT cidr FROM kevvpn_blocklist");
}

public void SqlCallback_ManualList(Database db, DBResultSet results, const char[] error, any data)
{
	if (results == null)
	{
		LogError("[KevVPN] Manual blocklist load failed: %s", error);
		return;
	}

	g_hManual.Clear();

	char sEntry[64];
	while (results.FetchRow())
	{
		results.FetchString(0, sEntry, sizeof(sEntry));

		int network, mask;
		if (!ParseCidr(sEntry, network, mask))
		{
			LogError("[KevVPN] Ignoring malformed manual blocklist entry '%s'.", sEntry);
			continue;
		}
		g_hManual.Push(network & mask);
		g_hManual.Set(g_hManual.Length - 1, mask, 1);
	}
	LogMessage("[KevVPN] Manual blocklist loaded (%d entries).", g_hManual.Length);
}

// ---- Allowed providers ----------------------------------------------------

void LoadProviders()
{
	if (!g_bDbReady)
		return;
	g_hDb.Query(SqlCallback_Providers, "SELECT name FROM kevvpn_providers");
}

public void SqlCallback_Providers(Database db, DBResultSet results, const char[] error, any data)
{
	if (results == null)
	{
		LogError("[KevVPN] Provider allowlist load failed: %s", error);
		return;
	}

	g_hProviders.Clear();

	char sName[64];
	while (results.FetchRow())
	{
		results.FetchString(0, sName, sizeof(sName));
		if (sName[0])
			g_hProviders.PushString(sName);
	}
	LogMessage("[KevVPN] Provider allowlist loaded (%d entries).", g_hProviders.Length);
}

public void SqlCallback_ProvidersChanged(Database db, DBResultSet results, const char[] error, any data)
{
	if (results == null)
	{
		LogError("[KevVPN] Provider allowlist write failed: %s", error);
		return;
	}
	LoadProviders();
}

bool FindManualMatch(const char[] sIp, char[] sOut, int iOutLen)
{
	int ip = IpToInt(sIp);
	if (ip == 0)
		return false;

	for (int i = 0; i < g_hManual.Length; i++)
	{
		int mask = g_hManual.Get(i, 1);
		if ((ip & mask) == g_hManual.Get(i, 0))
		{
			char sNet[MAX_IP_LEN];
			IntToIp(g_hManual.Get(i, 0), sNet, sizeof(sNet));
			FormatEx(sOut, iOutLen, "%s/%d", sNet, MaskToPrefix(mask));
			return true;
		}
	}
	return false;
}

// Accepts "1.2.3.4" (treated as /32) or "1.2.3.0/24".
bool ParseCidr(const char[] sInput, int &network, int &mask)
{
	char sWork[64];
	strcopy(sWork, sizeof(sWork), sInput);
	TrimString(sWork);

	int prefix = 32;
	int iSlash = FindCharInString(sWork, '/');
	if (iSlash != -1)
	{
		prefix = StringToInt(sWork[iSlash + 1]);
		sWork[iSlash] = '\0';
		if (prefix < 0 || prefix > 32)
			return false;
	}

	network = IpToInt(sWork);
	if (network == 0)
		return false;

	mask = (prefix == 0) ? 0 : (-1 << (32 - prefix));
	network &= mask;
	return true;
}

int MaskToPrefix(int mask)
{
	int bits = 0;
	for (int i = 0; i < 32; i++)
	{
		if (!(mask & (1 << (31 - i))))
			break;
		bits++;
	}
	return bits;
}

int IpToInt(const char[] sIp)
{
	char sOctets[4][8];
	if (ExplodeString(sIp, ".", sOctets, sizeof(sOctets), sizeof(sOctets[])) != 4)
		return 0;

	int result = 0;
	for (int i = 0; i < 4; i++)
	{
		int v = StringToInt(sOctets[i]);
		if (v < 0 || v > 255)
			return 0;
		result |= (v & 0xFF) << (24 - i * 8);
	}
	return result;
}

void IntToIp(int ip, char[] sOut, int iOutLen)
{
	FormatEx(sOut, iOutLen, "%d.%d.%d.%d",
		(ip >>> 24) & 0xFF, (ip >>> 16) & 0xFF, (ip >>> 8) & 0xFF, ip & 0xFF);
}

// ---- Blocklist files ------------------------------------------------------

void LoadAllLists()
{
	ClearCidr();

	char sDir[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, sDir, sizeof(sDir), "data/kevvpn/lists");
	if (!DirExists(sDir))
		return;

	DirectoryListing dir = OpenDirectory(sDir);
	if (dir == null)
		return;

	char sName[PLATFORM_MAX_PATH], sPath[PLATFORM_MAX_PATH];
	FileType type;
	int iFiles = 0;

	while (dir.GetNext(sName, sizeof(sName), type))
	{
		if (type != FileType_File)
			continue;
		FormatEx(sPath, sizeof(sPath), "%s/%s", sDir, sName);
		iFiles += LoadListFile(sPath) ? 1 : 0;
	}
	delete dir;

	LogMessage("[KevVPN] Loaded %d ranges from %d blocklist file%s.", g_iCidrCount, iFiles, iFiles == 1 ? "" : "s");
}

bool LoadListFile(const char[] sPath)
{
	File hFile = OpenFile(sPath, "r");
	if (hFile == null)
		return false;

	char sLine[128];
	while (hFile.ReadLine(sLine, sizeof(sLine)))
	{
		// firehol and Umkus files carry large "#" header blocks.
		int iComment = FindCharInString(sLine, '#');
		if (iComment != -1)
			sLine[iComment] = '\0';
		iComment = FindCharInString(sLine, ';');
		if (iComment != -1)
			sLine[iComment] = '\0';
		TrimString(sLine);
		if (!sLine[0])
			continue;

		// Same parser as the manual blocklist so the two can't drift; it also rejects 0.0.0.0.
		int network, mask;
		if (!ParseCidr(sLine, network, mask))
			continue;

		AddCidr(network, mask);
	}
	hFile.Close();
	return true;
}

public Action Timer_Update(Handle timer)
{
	StartDownloads();
	return Plugin_Continue;
}

// Deletes every downloaded list. Files are named by position, so dropping a URL from
// sources.ini orphans the old list_N.netset and LoadAllLists reads the whole folder.
void WipeDownloadedLists()
{
	char sDir[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, sDir, sizeof(sDir), "data/kevvpn/lists");

	DirectoryListing dir = OpenDirectory(sDir);
	if (dir == null)
		return;

	char sName[PLATFORM_MAX_PATH], sPath[PLATFORM_MAX_PATH];
	FileType type;
	int iDeleted = 0;

	while (dir.GetNext(sName, sizeof(sName), type))
	{
		if (type != FileType_File)
			continue;
		FormatEx(sPath, sizeof(sPath), "%s/%s", sDir, sName);
		if (DeleteFile(sPath))
			iDeleted++;
	}
	delete dir;

	LogMessage("[KevVPN] Deleted %d downloaded blocklist file(s).", iDeleted);
}

void StartDownloads()
{
	if (!g_bExtReady || g_iPendingDownloads > 0)
		return;

	char sPath[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, sPath, sizeof(sPath), "configs/kevvpn/sources.ini");
	if (!FileExists(sPath))
	{
		WriteDefaultSources(sPath);
		LogMessage("[KevVPN] Created a default source list at %s.", sPath);
	}

	File hFile = OpenFile(sPath, "r");
	if (hFile == null)
		return;

	char sDir[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, sDir, sizeof(sDir), "data/kevvpn/lists");

	char sUrl[MAX_URL_LEN], sOut[PLATFORM_MAX_PATH];
	int iIndex = 0;

	while (hFile.ReadLine(sUrl, sizeof(sUrl)))
	{
		int iComment = FindCharInString(sUrl, '#');
		if (iComment != -1)
			sUrl[iComment] = '\0';
		TrimString(sUrl);
		if (StrContains(sUrl, "http", false) != 0)
			continue;

		FormatEx(sOut, sizeof(sOut), "%s/list_%d.netset", sDir, iIndex++);

		g_iPendingDownloads++;
		HTTPRequest request = new HTTPRequest(sUrl);
		request.DownloadFile(sOut, OnListDownloaded);
	}
	hFile.Close();

	if (g_iPendingDownloads == 0)
		LogMessage("[KevVPN] No usable source URLs found in configs/kevvpn/sources.ini.");
}

public void OnListDownloaded(HTTPStatus status, any value, const char[] error)
{
	if (error[0] != '\0')
		LogError("[KevVPN] Blocklist download failed: %s", error);
	else if (status != HTTPStatus_OK)
		LogError("[KevVPN] Blocklist download returned HTTP %d.", view_as<int>(status));

	// Reload once, after the last one lands, rather than per file.
	if (--g_iPendingDownloads <= 0)
	{
		g_iPendingDownloads = 0;
		LoadAllLists();
	}
}

void WriteDefaultSources(const char[] sPath)
{
	File hFile = OpenFile(sPath, "w");
	if (hFile == null)
		return;

	hFile.WriteLine("// KevVPN blocklist sources. One URL per line, '#' or '//' comments.");
	hFile.WriteLine("// Each file must be a plain list of CIDR ranges or bare addresses.");
	hFile.WriteLine("// Every URL below was fetched and confirmed to exist and to be in");
	hFile.WriteLine("// that format. A dead URL is logged and the others still load.");
	hFile.WriteLine("");
	hFile.WriteLine("// ---- PRIMARY: VPN egress and datacenter ranges ----");
	hFile.WriteLine("// X4BNet/lists_vpn. Plain CIDR, small, actively maintained, and the");
	hFile.WriteLine("// closest free equivalent of udger's paid datacenter database.");
	hFile.WriteLine("// vpn ~3,900 ranges, datacenter ~15,000 ranges.");
	hFile.WriteLine("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt");
	hFile.WriteLine("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt");
	hFile.WriteLine("");
	hFile.WriteLine("// ---- SUPPLEMENT: tor exits ----");
	hFile.WriteLine("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dm_tor.ipset");
	hFile.WriteLine("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/et_tor.ipset");
	hFile.WriteLine("");
	hFile.WriteLine("// ---- PER-ASN: providers the general lists miss ----");
	hFile.WriteLine("// ipverse/asn-ip publishes every announced prefix per ASN as plain");
	hFile.WriteLine("// CIDR. Swap the number for any AS you want covered.");
	hFile.WriteLine("//");
	hFile.WriteLine("// AS13335 Cloudflare. Needed for WARP: its egress lives in 104.28.0.0/16,");
	hFile.WriteLine("// which is NOT in Cloudflare's published CDN list at cloudflare.com/ips-v4");
	hFile.WriteLine("// and is not in the datacenter feed either. No consumer ISP is Cloudflare,");
	hFile.WriteLine("// so blocking this AS only affects WARP users.");
	hFile.WriteLine("https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13335/ipv4-aggregated.txt");
	hFile.WriteLine("");
	hFile.WriteLine("// ---- DELIBERATELY NOT INCLUDED ----");
	hFile.WriteLine("// firehol_proxies.netset is 37 MB and roughly 2.5 MILLION entries,");
	hFile.WriteLine("// mostly single addresses of transient open proxies. Loading it takes");
	hFile.WriteLine("// most of a gigabyte of process memory, and a large share of those");
	hFile.WriteLine("// addresses are compromised home machines, which on a game server is a");
	hFile.WriteLine("// real player. Same objection as firehol Level 2. Not worth it.");
	hFile.WriteLine("// firehol_anonymous.netset is 10 MB+ with the same problem.");
	hFile.WriteLine("");
	hFile.WriteLine("// ---- DO NOT ADD firehol Level 1 or Level 2 ----");
	hFile.WriteLine("// dshield, spamhaus_drop/edrop, abuse.ch (feodo/zeus/sslbl/palevo),");
	hFile.WriteLine("// blocklist_de, openbl and bogons track ATTACKERS, not VPNs. They");
	hFile.WriteLine("// will not contain a commercial VPN exit, and blocklist_de/openbl in");
	hFile.WriteLine("// particular list individual home addresses that ran a brute-force");
	hFile.WriteLine("// attack, which on a game server is usually a player with malware or");
	hFile.WriteLine("// a recycled dynamic IP. Adding them buys no detection and creates");
	hFile.WriteLine("// false positives. bogons are unroutable and can never be a client.");
	hFile.WriteLine("");
	hFile.WriteLine("// ---- udger ----");
	hFile.WriteLine("// https://udger.com/resources/datacenter-list is the best datacenter");
	hFile.WriteLine("// dataset (1,920 datacenters / 37,414 ranges) but it is subscription");
	hFile.WriteLine("// only, delivered as SQLite3 from data.udger.com/[ACCESS_KEY]/, so it");
	hFile.WriteLine("// cannot be fetched here. With a subscription, export the ranges to a");
	hFile.WriteLine("// plain CIDR file and drop it into addons/sourcemod/data/kevvpn/lists/");
	hFile.WriteLine("// - any file in that folder is parsed whether or not it came from a URL.");
	hFile.Close();
}

// ---- Whitelist ------------------------------------------------------------

void LoadWhitelist()
{
	if (!g_bDbReady)
		return;
	g_hDb.Query(SqlCallback_Whitelist, "SELECT identity FROM kevvpn_whitelist");
}

public void SqlCallback_Whitelist(Database db, DBResultSet results, const char[] error, any data)
{
	if (results == null)
	{
		LogError("[KevVPN] Whitelist load failed: %s", error);
		return;
	}

	g_hWhitelist.Clear();

	char sEntry[64];
	while (results.FetchRow())
	{
		results.FetchString(0, sEntry, sizeof(sEntry));
		// Normalized on load as well as on write, so hand-edited or older rows still match.
		NormalizeSteamId(sEntry, sizeof(sEntry));
		g_hWhitelist.PushString(sEntry);
	}
	LogMessage("[KevVPN] Whitelist loaded (%d entries).", g_hWhitelist.Length);
}

bool IsWhitelisted(int client, const char[] sIp)
{
	char sAuth[32];
	bool bHasAuth = GetClientAuthId(client, AuthId_Steam2, sAuth, sizeof(sAuth));

	char sEntry[64];
	for (int i = 0; i < g_hWhitelist.Length; i++)
	{
		g_hWhitelist.GetString(i, sEntry, sizeof(sEntry));
		if (bHasAuth && StrEqual(sEntry, sAuth, false))
			return true;
		if (StrEqual(sEntry, sIp))
			return true;
	}
	return false;
}

// STEAM_0:1:123 and STEAM_1:1:123 are the SAME account. CS:GO reports universe 1, most
// copy-paste sources print universe 0. Comparing literally fails silently, which is how a
// whitelist entry that looks right does nothing. Stored and compared as universe 1.
void NormalizeSteamId(char[] sId, int iLen)
{
	if (StrContains(sId, "STEAM_", false) != 0)
		return;
	if (iLen < 8 || !IsCharNumeric(sId[6]) || sId[7] != ':')
		return;
	sId[6] = '1';
}

int FindClientByIp(const char[] sIp)
{
	char sOther[MAX_IP_LEN];
	for (int i = 1; i <= MaxClients; i++)
	{
		if (!IsClientInGame(i) || IsFakeClient(i))
			continue;
		if (GetClientIP(i, sOther, sizeof(sOther), true) && StrEqual(sOther, sIp))
			return i;
	}
	return 0;
}

// Turns a command argument into a SteamID2 or an IP, accepting a live player by name or
// userid, the common case after a false positive. bPreferAuth is for the whitelist: an
// address is a poor key there because VPN and mobile exits hand out a new one each
// session, so store the SteamID when the player is on the server.
bool ResolveTarget(int client, const char[] sArg, char[] sOut, int iOutLen, bool bPreferAuth = false)
{
	if (StrContains(sArg, "STEAM_", false) == 0)
	{
		strcopy(sOut, iOutLen, sArg);
		NormalizeSteamId(sOut, iOutLen);
		return true;
	}
	if (IpToInt(sArg) != 0)
	{
		if (bPreferAuth)
		{
			int iOwner = FindClientByIp(sArg);
			if (iOwner > 0 && GetClientAuthId(iOwner, AuthId_Steam2, sOut, iOutLen))
			{
				ReplyToCommand(client, "[KevVPN] %s is %N. Whitelisting their SteamID %s instead, which survives an address change.",
					sArg, iOwner, sOut);
				return true;
			}
			ReplyToCommand(client, "[KevVPN] Warning: whitelisting a bare address. If they reconnect on a different one it stops matching. A SteamID is the durable key.");
		}
		strcopy(sOut, iOutLen, sArg);
		return true;
	}

	int target = FindTarget(client, sArg, true, false);
	if (target < 1)
		return false; // FindTarget already replied

	if (!GetClientAuthId(target, AuthId_Steam2, sOut, iOutLen))
	{
		ReplyToCommand(client, "[KevVPN] Could not read that player's SteamID.");
		return false;
	}
	return true;
}

// Reads the raw argument string, because the engine tokenizer splits an unquoted STEAM_1:0:X on its colons.
void SplitRawArgs(char[] sFirst, int iFirstLen, char[] sRest, int iRestLen)
{
	char sRaw[256];
	GetCmdArgString(sRaw, sizeof(sRaw));
	TrimString(sRaw);

	sFirst[0] = '\0';
	sRest[0] = '\0';
	if (!sRaw[0])
		return;

	if (sRaw[0] == '"')
	{
		int iClose = FindCharInString(sRaw[1], '"');
		if (iClose != -1)
		{
			sRaw[iClose + 1] = '\0';
			strcopy(sFirst, iFirstLen, sRaw[1]);
			strcopy(sRest, iRestLen, sRaw[iClose + 2]);
			TrimString(sRest);
			return;
		}
	}

	int iCut = FindCharInString(sRaw, ' ');
	if (iCut == -1)
	{
		strcopy(sFirst, iFirstLen, sRaw);
		return;
	}
	sRaw[iCut] = '\0';
	strcopy(sFirst, iFirstLen, sRaw);
	strcopy(sRest, iRestLen, sRaw[iCut + 1]);
	TrimString(sRest);
}

// ---- Commands -------------------------------------------------------------

public Action Command_Whitelist(int client, int args)
{
	if (args < 1 || !g_bDbReady)
	{
		ReplyToCommand(client, g_bDbReady
			? "[KevVPN] Usage: sm_kevvpn_whitelist <#userid|name|STEAM_1:0:X> [comment] - a SteamID is stored wherever possible, since addresses rotate."
			: "[KevVPN] The database is not connected.");
		return Plugin_Handled;
	}

	char sArg[64], sComment[128], sEntry[64];
	SplitRawArgs(sArg, sizeof(sArg), sComment, sizeof(sComment));

	// bPreferAuth: resolve an address to its owner's SteamID when we can.
	if (!ResolveTarget(client, sArg, sEntry, sizeof(sEntry), true))
		return Plugin_Handled;

	if (g_hWhitelist.FindString(sEntry) != -1)
	{
		ReplyToCommand(client, "[KevVPN] %s is already whitelisted.", sEntry);
		return Plugin_Handled;
	}

	char sAdmin[32];
	if (client < 1 || !GetClientAuthId(client, AuthId_Steam2, sAdmin, sizeof(sAdmin)))
		strcopy(sAdmin, sizeof(sAdmin), "CONSOLE");

	char sEntryEsc[128], sCommentEsc[260], sAdminEsc[64], sQuery[640];
	g_hDb.Escape(sEntry, sEntryEsc, sizeof(sEntryEsc));
	g_hDb.Escape(sComment, sCommentEsc, sizeof(sCommentEsc));
	g_hDb.Escape(sAdmin, sAdminEsc, sizeof(sAdminEsc));

	FormatEx(sQuery, sizeof(sQuery),
		"%s INTO kevvpn_whitelist (identity, added_by, comment, added) VALUES ('%s', '%s', '%s', %d)",
		g_bSqlite ? "INSERT OR REPLACE" : "REPLACE", sEntryEsc, sAdminEsc, sCommentEsc, GetTime());
	g_hDb.Query(SqlCallback_WhitelistChanged, sQuery);

	ReplyToCommand(client, "[KevVPN] Whitelisted %s.", sEntry);
	LogAction(client, -1, "\"%L\" whitelisted %s in KevVPN", client, sEntry);
	return Plugin_Handled;
}

public Action Command_Unwhitelist(int client, int args)
{
	if (args < 1 || !g_bDbReady)
	{
		ReplyToCommand(client, g_bDbReady
			? "[KevVPN] Usage: sm_kevvpn_unwhitelist <#userid|name|STEAM_1:0:X|1.2.3.4>"
			: "[KevVPN] The database is not connected.");
		return Plugin_Handled;
	}

	char sArg[64], sRest[128], sEntry[64];
	SplitRawArgs(sArg, sizeof(sArg), sRest, sizeof(sRest));

	if (!ResolveTarget(client, sArg, sEntry, sizeof(sEntry)))
		return Plugin_Handled;

	// sEntry is universe 1, but rows written before that, or added by hand as universe 0, still need removing.
	char sLegacy[64];
	strcopy(sLegacy, sizeof(sLegacy), sEntry);
	if (StrContains(sLegacy, "STEAM_", false) == 0 && strlen(sLegacy) > 7)
		sLegacy[6] = '0';

	char sEntryEsc[128], sLegacyEsc[128], sQuery[384];
	g_hDb.Escape(sEntry, sEntryEsc, sizeof(sEntryEsc));
	g_hDb.Escape(sLegacy, sLegacyEsc, sizeof(sLegacyEsc));
	FormatEx(sQuery, sizeof(sQuery),
		"DELETE FROM kevvpn_whitelist WHERE identity = '%s' OR identity = '%s'", sEntryEsc, sLegacyEsc);
	g_hDb.Query(SqlCallback_WhitelistChanged, sQuery);

	ReplyToCommand(client, "[KevVPN] Removed %s from the whitelist.", sEntry);
	LogAction(client, -1, "\"%L\" removed %s from the KevVPN whitelist", client, sEntry);
	return Plugin_Handled;
}

public void SqlCallback_WhitelistChanged(Database db, DBResultSet results, const char[] error, any data)
{
	if (results == null)
	{
		LogError("[KevVPN] Whitelist write failed: %s", error);
		return;
	}
	LoadWhitelist();
}

public Action Command_List(int client, int args)
{
	ReplyToCommand(client, "[KevVPN] %d whitelist entr%s:", g_hWhitelist.Length, g_hWhitelist.Length == 1 ? "y" : "ies");

	char sEntry[64];
	for (int i = 0; i < g_hWhitelist.Length; i++)
	{
		g_hWhitelist.GetString(i, sEntry, sizeof(sEntry));
		ReplyToCommand(client, "  %s", sEntry);
	}
	return Plugin_Handled;
}

public Action Command_Alts(int client, int args)
{
	if (args < 1 || !g_bDbReady)
	{
		ReplyToCommand(client, g_bDbReady
			? "[KevVPN] Usage: sm_kevvpn_alts <#userid|name|STEAM_1:0:X>"
			: "[KevVPN] The database is not connected.");
		return Plugin_Handled;
	}

	char sArg[64], sRest[128], sAuth[64];
	SplitRawArgs(sArg, sizeof(sArg), sRest, sizeof(sRest));

	if (!ResolveTarget(client, sArg, sAuth, sizeof(sAuth)))
		return Plugin_Handled;
	if (StrContains(sAuth, "STEAM_", false) != 0)
	{
		ReplyToCommand(client, "[KevVPN] Give a player or a SteamID, not an address.");
		return Plugin_Handled;
	}

	// LEFT JOIN so an address with no stored verdict still lists, as UNKNOWN. COALESCE behaves the
	// same on MySQL and SQLite. Deliberately NOT filtered by the cache TTL: the TTL decides when
	// to re-check, it must never hide history.
	char sAuthEsc[128], sQuery[768];
	g_hDb.Escape(sAuth, sAuthEsc, sizeof(sAuthEsc));
	// Match either universe, since history rows predate the normalization.
	char sLegacy[64], sLegacyEsc[128];
	strcopy(sLegacy, sizeof(sLegacy), sAuth);
	if (strlen(sLegacy) > 7)
		sLegacy[6] = '0';
	g_hDb.Escape(sLegacy, sLegacyEsc, sizeof(sLegacyEsc));

	FormatEx(sQuery, sizeof(sQuery),
		"SELECT p.ip, COALESCE(i.verdict, 0), COALESCE(i.source, ''), COALESCE(i.provider, ''), p.last_seen \
		FROM kevvpn_players p LEFT JOIN kevvpn_ips i ON i.ip = p.ip \
		WHERE p.steamid = '%s' OR p.steamid = '%s' ORDER BY p.last_seen DESC LIMIT 200",
		sAuthEsc, sLegacyEsc);

	g_hDb.Query(SqlCallback_Alts, sQuery, client < 1 ? -1 : GetClientUserId(client));
	return Plugin_Handled;
}

public void SqlCallback_Alts(Database db, DBResultSet results, const char[] error, any userid)
{
	// -1 is the server console, which is a real caller here, not a sentinel.
	int admin = (userid == -1) ? 0 : GetClientOfUserId(userid);
	if (userid != -1 && admin < 1)
		return;

	if (results == null)
	{
		AltsReply(admin, "[KevVPN] Lookup failed: %s", error);
		return;
	}
	if (results.RowCount == 0)
	{
		AltsReply(admin, "[KevVPN] No recorded addresses for that player.");
		return;
	}

	AltsReply(admin, "[KevVPN] List of recorded IP addresses (%d):", results.RowCount);

	char sIp[64], sSource[32], sProvider[64], sWhen[32];
	while (results.FetchRow())
	{
		results.FetchString(0, sIp, sizeof(sIp));
		int verdict = results.FetchInt(1);
		results.FetchString(2, sSource, sizeof(sSource));
		results.FetchString(3, sProvider, sizeof(sProvider));
		FormatTime(sWhen, sizeof(sWhen), "%Y-%m-%d", results.FetchInt(4));

		char sVerdict[16];
		if (verdict == VERDICT_BLOCKED)
			strcopy(sVerdict, sizeof(sVerdict), "VPN");
		else if (verdict == VERDICT_CLEAN)
			strcopy(sVerdict, sizeof(sVerdict), "CLEAN");
		else
			strcopy(sVerdict, sizeof(sVerdict), "UNKNOWN");

		// "1.2.3.4 - VPN - CIDR (NordVPN)"
		char sLine[224];
		FormatEx(sLine, sizeof(sLine), "  %s - %s", sIp, sVerdict);
		if (sSource[0])
			Format(sLine, sizeof(sLine), "%s - %s", sLine, sSource);
		if (sProvider[0])
			Format(sLine, sizeof(sLine), "%s (%s)", sLine, sProvider);
		Format(sLine, sizeof(sLine), "%s | last seen %s", sLine, sWhen);

		AltsReply(admin, "%s", sLine);
	}
}

void AltsReply(int admin, const char[] format, any ...)
{
	char sBuffer[256];
	VFormat(sBuffer, sizeof(sBuffer), format, 3);

	if (admin < 1)
		PrintToServer("%s", sBuffer);
	else if (IsClientInGame(admin))
		PrintToConsole(admin, "%s", sBuffer);
}

public Action Command_AddVpn(int client, int args)
{
	if (args < 1 || !g_bDbReady)
	{
		ReplyToCommand(client, g_bDbReady
			? "[KevVPN] Usage: sm_kevvpn_addvpn <1.2.3.4|1.2.3.0/24> [comment]"
			: "[KevVPN] The database is not connected.");
		return Plugin_Handled;
	}

	char sArg[64], sComment[128];
	SplitRawArgs(sArg, sizeof(sArg), sComment, sizeof(sComment));

	int network, mask;
	if (!ParseCidr(sArg, network, mask))
	{
		ReplyToCommand(client, "[KevVPN] '%s' is not a valid address or range. Expected 1.2.3.4 or 1.2.3.0/24.", sArg);
		return Plugin_Handled;
	}

	// Store the normalized form, so 1.2.3.7/24 and 1.2.3.0/24 cannot both exist.
	char sNet[MAX_IP_LEN], sCidr[48];
	IntToIp(network, sNet, sizeof(sNet));
	FormatEx(sCidr, sizeof(sCidr), "%s/%d", sNet, MaskToPrefix(mask));

	char sAdmin[32];
	if (client < 1 || !GetClientAuthId(client, AuthId_Steam2, sAdmin, sizeof(sAdmin)))
		strcopy(sAdmin, sizeof(sAdmin), "CONSOLE");

	char sCidrEsc[128], sCommentEsc[260], sAdminEsc[64], sQuery[640];
	g_hDb.Escape(sCidr, sCidrEsc, sizeof(sCidrEsc));
	g_hDb.Escape(sComment, sCommentEsc, sizeof(sCommentEsc));
	g_hDb.Escape(sAdmin, sAdminEsc, sizeof(sAdminEsc));

	FormatEx(sQuery, sizeof(sQuery),
		"%s INTO kevvpn_blocklist (cidr, added_by, comment, added) VALUES ('%s', '%s', '%s', %d)",
		g_bSqlite ? "INSERT OR REPLACE" : "REPLACE", sCidrEsc, sAdminEsc, sCommentEsc, GetTime());
	g_hDb.Query(SqlCallback_ManualChanged, sQuery);

	ReplyToCommand(client, "[KevVPN] Manually blocked %s.", sCidr);
	LogAction(client, -1, "\"%L\" manually blocked %s in KevVPN", client, sCidr);
	return Plugin_Handled;
}

public Action Command_DelVpn(int client, int args)
{
	if (args < 1 || !g_bDbReady)
	{
		ReplyToCommand(client, g_bDbReady
			? "[KevVPN] Usage: sm_kevvpn_delvpn <1.2.3.4|1.2.3.0/24>"
			: "[KevVPN] The database is not connected.");
		return Plugin_Handled;
	}

	char sArg[64], sRest[128];
	SplitRawArgs(sArg, sizeof(sArg), sRest, sizeof(sRest));

	int network, mask;
	if (!ParseCidr(sArg, network, mask))
	{
		ReplyToCommand(client, "[KevVPN] '%s' is not a valid address or range.", sArg);
		return Plugin_Handled;
	}

	char sNet[MAX_IP_LEN], sCidr[48], sCidrEsc[128], sQuery[256];
	IntToIp(network, sNet, sizeof(sNet));
	FormatEx(sCidr, sizeof(sCidr), "%s/%d", sNet, MaskToPrefix(mask));
	g_hDb.Escape(sCidr, sCidrEsc, sizeof(sCidrEsc));

	FormatEx(sQuery, sizeof(sQuery), "DELETE FROM kevvpn_blocklist WHERE cidr = '%s'", sCidrEsc);
	g_hDb.Query(SqlCallback_ManualChanged, sQuery);

	ReplyToCommand(client, "[KevVPN] Removed %s from the manual blocklist.", sCidr);
	LogAction(client, -1, "\"%L\" removed the manual KevVPN block on %s", client, sCidr);
	return Plugin_Handled;
}

public void SqlCallback_ManualChanged(Database db, DBResultSet results, const char[] error, any data)
{
	if (results == null)
	{
		LogError("[KevVPN] Manual blocklist write failed: %s", error);
		return;
	}
	LoadManualBlocklist();
}

public Action Command_VpnList(int client, int args)
{
	if (!g_bDbReady)
	{
		ReplyToCommand(client, "[KevVPN] The database is not connected.");
		return Plugin_Handled;
	}
	g_hDb.Query(SqlCallback_VpnList,
		"SELECT cidr, added_by, comment FROM kevvpn_blocklist ORDER BY added DESC",
		client < 1 ? -1 : GetClientUserId(client));
	return Plugin_Handled;
}

public void SqlCallback_VpnList(Database db, DBResultSet results, const char[] error, any userid)
{
	int admin = (userid == -1) ? 0 : GetClientOfUserId(userid);
	if (userid != -1 && admin < 1)
		return;

	if (results == null)
	{
		AltsReply(admin, "[KevVPN] Lookup failed: %s", error);
		return;
	}

	AltsReply(admin, "[KevVPN] %d manually blocked entr%s:", results.RowCount, results.RowCount == 1 ? "y" : "ies");

	char sCidr[64], sBy[64], sComment[160];
	while (results.FetchRow())
	{
		results.FetchString(0, sCidr, sizeof(sCidr));
		results.FetchString(1, sBy, sizeof(sBy));
		results.FetchString(2, sComment, sizeof(sComment));
		AltsReply(admin, "  %s - by %s%s%s", sCidr, sBy, sComment[0] ? " | " : "", sComment);
	}
}

public Action Command_AllowDc(int client, int args)
{
	if (args < 1 || !g_bDbReady)
	{
		ReplyToCommand(client, g_bDbReady
			? "[KevVPN] Usage: sm_kevvpn_allowdc <provider name> [comment]   e.g. sm_kevvpn_allowdc NVIDIA"
			: "[KevVPN] The database is not connected.");
		return Plugin_Handled;
	}

	char sName[64], sComment[128];
	SplitRawArgs(sName, sizeof(sName), sComment, sizeof(sComment));
	if (!sName[0])
		return Plugin_Handled;

	char sAdmin[32];
	if (client < 1 || !GetClientAuthId(client, AuthId_Steam2, sAdmin, sizeof(sAdmin)))
		strcopy(sAdmin, sizeof(sAdmin), "CONSOLE");

	char sNameEsc[160], sCommentEsc[260], sAdminEsc[64], sQuery[640];
	g_hDb.Escape(sName, sNameEsc, sizeof(sNameEsc));
	g_hDb.Escape(sComment, sCommentEsc, sizeof(sCommentEsc));
	g_hDb.Escape(sAdmin, sAdminEsc, sizeof(sAdminEsc));

	FormatEx(sQuery, sizeof(sQuery),
		"%s INTO kevvpn_providers (name, added_by, comment, added) VALUES ('%s', '%s', '%s', %d)",
		g_bSqlite ? "INSERT OR REPLACE" : "REPLACE", sNameEsc, sAdminEsc, sCommentEsc, GetTime());
	g_hDb.Query(SqlCallback_ProvidersChanged, sQuery);

	ReplyToCommand(client, "[KevVPN] Provider '%s' is now allowed. Addresses reported as this provider are let through even when a range matches.", sName);
	LogAction(client, -1, "\"%L\" allowed KevVPN provider '%s'", client, sName);
	return Plugin_Handled;
}

public Action Command_DenyDc(int client, int args)
{
	if (args < 1 || !g_bDbReady)
	{
		ReplyToCommand(client, g_bDbReady
			? "[KevVPN] Usage: sm_kevvpn_denydc <provider name>"
			: "[KevVPN] The database is not connected.");
		return Plugin_Handled;
	}

	char sName[64], sRest[128];
	SplitRawArgs(sName, sizeof(sName), sRest, sizeof(sRest));
	if (!sName[0])
		return Plugin_Handled;

	char sNameEsc[160], sQuery[256];
	g_hDb.Escape(sName, sNameEsc, sizeof(sNameEsc));
	FormatEx(sQuery, sizeof(sQuery), "DELETE FROM kevvpn_providers WHERE name = '%s'", sNameEsc);
	g_hDb.Query(SqlCallback_ProvidersChanged, sQuery);

	ReplyToCommand(client, "[KevVPN] Provider '%s' is no longer allowed.", sName);
	LogAction(client, -1, "\"%L\" removed KevVPN provider allowance '%s'", client, sName);
	return Plugin_Handled;
}

public Action Command_DcList(int client, int args)
{
	if (!g_bDbReady)
	{
		ReplyToCommand(client, "[KevVPN] The database is not connected.");
		return Plugin_Handled;
	}
	g_hDb.Query(SqlCallback_DcList,
		"SELECT name, added_by, comment FROM kevvpn_providers ORDER BY name",
		client < 1 ? -1 : GetClientUserId(client));
	return Plugin_Handled;
}

public void SqlCallback_DcList(Database db, DBResultSet results, const char[] error, any userid)
{
	int admin = (userid == -1) ? 0 : GetClientOfUserId(userid);
	if (userid != -1 && admin < 1)
		return;

	if (results == null)
	{
		AltsReply(admin, "[KevVPN] Lookup failed: %s", error);
		return;
	}

	AltsReply(admin, "[KevVPN] %d allowed provider%s:", results.RowCount, results.RowCount == 1 ? "" : "s");

	char sName[64], sBy[64], sComment[160];
	while (results.FetchRow())
	{
		results.FetchString(0, sName, sizeof(sName));
		results.FetchString(1, sBy, sizeof(sBy));
		results.FetchString(2, sComment, sizeof(sComment));
		AltsReply(admin, "  %s - by %s%s%s", sName, sBy, sComment[0] ? " | " : "", sComment);
	}
}

// The three DB-backed lists are cached in memory so the join check stays synchronous.
// Editing the tables with SQL changes nothing until they are re-read.
public Action Command_Reload(int client, int args)
{
	if (!g_bDbReady)
	{
		ReplyToCommand(client, "[KevVPN] The database is not connected.");
		return Plugin_Handled;
	}

	LoadWhitelist();
	LoadManualBlocklist();
	LoadProviders();

	ReplyToCommand(client, "[KevVPN] Re-reading whitelist, manual blocklist and provider allowlist; counts appear in the log.");
	return Plugin_Handled;
}

public Action Command_Update(int client, int args)
{
	if (!g_bExtReady)
	{
		ReplyToCommand(client, "[KevVPN] REST in Pawn is not loaded, cannot download.");
		return Plugin_Handled;
	}
	if (g_iPendingDownloads > 0)
	{
		ReplyToCommand(client, "[KevVPN] An update is already running (%d file(s) outstanding).", g_iPendingDownloads);
		return Plugin_Handled;
	}

	char sArg[16];
	if (args >= 1)
		GetCmdArg(1, sArg, sizeof(sArg));

	if (StrEqual(sArg, "clean", false))
	{
		WipeDownloadedLists();
		ClearCidr();
		ReplyToCommand(client, "[KevVPN] Wiped the downloaded lists first.");
	}

	StartDownloads();
	ReplyToCommand(client, "[KevVPN] Downloading %d blocklist file(s); the log will report the new range count.", g_iPendingDownloads);
	return Plugin_Handled;
}

public Action Command_Check(int client, int args)
{
	if (args < 1)
	{
		ReplyToCommand(client, "[KevVPN] Usage: sm_kevvpn_check <#userid|name|1.2.3.4>");
		return Plugin_Handled;
	}

	char sArg[64], sRest[128], sIp[MAX_IP_LEN];
	SplitRawArgs(sArg, sizeof(sArg), sRest, sizeof(sRest));

	// A raw address has no player behind it, so it can only be reported on.
	int target = 0;
	if (IpToInt(sArg) != 0)
	{
		strcopy(sIp, sizeof(sIp), sArg);
	}
	else
	{
		target = FindTarget(client, sArg, true, false);
		if (target < 1)
			return Plugin_Handled;
		if (!GetClientIP(target, sIp, sizeof(sIp), true))
		{
			ReplyToCommand(client, "[KevVPN] Could not read that player's address.");
			return Plugin_Handled;
		}
	}

	char sRange[40];
	if (FindManualMatch(sIp, sRange, sizeof(sRange)))
	{
		ReplyToCommand(client, "[KevVPN] %s matches MANUAL block %s.", sIp, sRange);
		CheckPunish(client, target, sIp, "Manual", sRange);
		return Plugin_Handled;
	}
	if (FindCidrMatch(sIp, sRange, sizeof(sRange)))
	{
		ReplyToCommand(client, "[KevVPN] %s matches downloaded range %s.", sIp, sRange);
		CheckPunish(client, target, sIp, "CIDR", sRange);
		return Plugin_Handled;
	}
	ReplyToCommand(client, "[KevVPN] %s is in no blocked range.", sIp);

	CacheEntry entry;
	if (CacheGet(sIp, entry))
	{
		ReplyToCommand(client, "[KevVPN] Stored verdict: %s - %s%s%s%s",
			entry.verdict == VERDICT_BLOCKED ? "VPN" : "CLEAN",
			entry.source[0] ? entry.source : "unknown",
			entry.provider[0] ? " (" : "", entry.provider, entry.provider[0] ? ")" : "");

		if (entry.verdict == VERDICT_BLOCKED)
		{
			if (entry.provider[0] && IsProviderAllowed(entry.provider))
			{
				ReplyToCommand(client, "[KevVPN] That provider is on the allowlist, so this address is let through.");
			}
			else
			{
				char sDetail[96];
				FormatEx(sDetail, sizeof(sDetail), "(%s)", entry.provider[0] ? entry.provider : "provider unknown");
				CheckPunish(client, target, sIp, entry.source, sDetail);
			}
			return Plugin_Handled;
		}
	}
	else
	{
		ReplyToCommand(client, "[KevVPN] No stored verdict yet.");
	}

	// Actually asks a service rather than only reporting what is known. Without it the command
	// answered 'no blocked range' for an address every API would flag.
	if (g_bExtReady)
	{
		ReplyToCommand(client, "[KevVPN] Querying ip-api.com for a live opinion...");
		ProbeIpApi(client < 1 ? -1 : GetClientUserId(client),
			target > 0 ? GetClientUserId(target) : 0, sIp);
	}

	return Plugin_Handled;
}

// Punishes a target from sm_kevvpn_check with the same exemptions as the join path.
void CheckPunish(int admin, int target, const char[] sIp, const char[] sSource, const char[] sDetail)
{
	if (target < 1 || !IsClientInGame(target))
		return;

	if (IsExempt(target))
	{
		AltsReply(admin, "[KevVPN] %N is exempt from KevVPN checks, not acting.", target);
		return;
	}
	if (IsWhitelisted(target, sIp))
	{
		AltsReply(admin, "[KevVPN] %N is whitelisted, not acting.", target);
		return;
	}
	if (cv_Action.IntValue <= 0)
	{
		AltsReply(admin, "[KevVPN] kevvpn_action is 0 (log only), so nothing was enforced.");
	}

	Punish(target, sIp, sSource, sDetail);
}

// Admin-facing lookup for sm_kevvpn_check. Separate from the connect path: never caches,
// reports to the admin, and does punish when the check named a connected player. The IP
// travels in the request URL and is read back from the response.
void ProbeIpApi(int adminUserId, int targetUserId, const char[] sIp)
{
	char sUrl[MAX_URL_LEN];
	FormatEx(sUrl, sizeof(sUrl),
		"http://ip-api.com/json/%s?fields=status,query,proxy,hosting,mobile,isp,org", sIp);

	// Two userids will not fit in one cell safely, so they travel in a pack.
	DataPack pack = new DataPack();
	pack.WriteCell(adminUserId);
	pack.WriteCell(targetUserId);

	HTTPRequest request = new HTTPRequest(sUrl);
	request.Get(OnProbeDone, pack);
}

public void OnProbeDone(HTTPResponse response, any data, const char[] error)
{
	DataPack pack = view_as<DataPack>(data);
	pack.Reset();
	int adminUserId = pack.ReadCell();
	int targetUserId = pack.ReadCell();
	delete pack;

	int admin = (adminUserId == -1) ? 0 : GetClientOfUserId(adminUserId);
	if (adminUserId != -1 && admin < 1)
		return;

	int target = (targetUserId == 0) ? 0 : GetClientOfUserId(targetUserId);

	if (error[0] != '\0' || response.Status != HTTPStatus_OK || response.Data == null)
	{
		AltsReply(admin, "[KevVPN] Live lookup failed (%s).", error[0] ? error : "no usable response");
		return;
	}

	JSONObject root = view_as<JSONObject>(response.Data);

	char sStatus[16];
	root.GetString("status", sStatus, sizeof(sStatus));
	if (!StrEqual(sStatus, "success", false))
	{
		AltsReply(admin, "[KevVPN] Live lookup returned status '%s'.", sStatus);
		return;
	}

	char sQuery[64], sProvider[64];
	root.GetString("query", sQuery, sizeof(sQuery));
	if (!root.GetString("org", sProvider, sizeof(sProvider)) || !sProvider[0])
		root.GetString("isp", sProvider, sizeof(sProvider));

	bool bProxy   = root.HasKey("proxy")   && root.GetBool("proxy");
	bool bHosting = root.HasKey("hosting") && root.GetBool("hosting");
	bool bMobile  = root.HasKey("mobile")  && root.GetBool("mobile");

	AltsReply(admin, "[KevVPN] %s live: proxy=%s hosting=%s mobile=%s | %s",
		sQuery, bProxy ? "YES" : "no", bHosting ? "YES" : "no", bMobile ? "yes" : "no", sProvider);

	if (bProxy || bHosting)
	{
		if (sProvider[0] && IsProviderAllowed(sProvider))
		{
			AltsReply(admin, "[KevVPN] ALLOWED: provider is on the allowlist.");
			return;
		}

		AltsReply(admin, "[KevVPN] DETECTED as vpn/proxy/hosting.");

		// Store it so the next join short-circuits, and act now if the check named a live player.
		StoreVerdict(sQuery, VERDICT_BLOCKED, "IPAPI", sProvider);

		char sDetail[96];
		FormatEx(sDetail, sizeof(sDetail), "(%s)", sProvider[0] ? sProvider : "provider unknown");
		CheckPunish(admin, target, sQuery, "IPAPI", sDetail);
		return;
	}

	AltsReply(admin, "[KevVPN] Passes this layer. proxycheck.io may still disagree on a real join.");
}

public Action Command_Status(int client, int args)
{
	static const char sActionNames[][] = { "log only", "kick", "SourceMod ban", "SourceBans++ ban" };
	ReplyToCommand(client, "[KevVPN] %s | action: %s", PLUGIN_VERSION, sActionNames[cv_Action.IntValue]);
	ReplyToCommand(client, "[KevVPN] Ranges: %d downloaded, %d manual | memory cache: %d | whitelist: %d",
		g_iCidrCount, g_hManual.Length, g_hCache.Size, g_hWhitelist.Length);
	ReplyToCommand(client, "[KevVPN] Database: %s | REST in Pawn: %s",
		g_bDbReady ? (g_bSqlite ? "sqlite" : "mysql") : "NOT CONNECTED (enforcement suspended)",
		g_bExtReady ? "loaded" : "MISSING");
	ReplyToCommand(client, "[KevVPN] Layers - cidr: %s | proxycheck.io: %s | ip-api: %s | blackbox: %s",
		cv_UseCidr.BoolValue ? "on" : "off",
		cv_UseProxyCheck.BoolValue ? "on" : "off",
		cv_UseIpApi.BoolValue ? "on" : "off",
		cv_UseBlackbox.BoolValue ? "on" : "off");
	return Plugin_Handled;
}
