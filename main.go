package main

import (
    "context"
    "database/sql"
    "encoding/hex"
    "fmt"
    "log"
    "os"
    "os/user"
    "path/filepath"
    "strings"

    "github.com/osquery/osquery-go"
    "github.com/osquery/osquery-go/plugin/table"
    _ "github.com/mattn/go-sqlite3"
)

// Enable or disable debug logging here
var DEBUG string

func debugLog(format string, a ...interface{}) {
    if DEBUG == "true" {
        log.Printf("[DEBUG] "+format, a...)
    }
}

var tccColumns = []table.ColumnDefinition{
    table.TextColumn("type"), // user/system
    table.TextColumn("username"),
    table.TextColumn("service"),
    table.TextColumn("client"),
    table.IntegerColumn("client_type"),
    table.IntegerColumn("auth_value"),
    table.IntegerColumn("auth_reason"),
    table.IntegerColumn("auth_version"),
    table.TextColumn("csreq"),
    table.TextColumn("policy_id"),
    table.IntegerColumn("indirect_object_identifier_type"),
    table.TextColumn("indirect_object_identifier"),
    table.TextColumn("indirect_object_code_identity"),
    table.IntegerColumn("flags"),
    table.IntegerColumn("last_modified"),
}

// Helper to convert BLOB columns to hex strings
func bytesToHexString(b []byte) string {
    if b == nil {
        return ""
    }
    return hex.EncodeToString(b)
}

// Helper for nullable ints
func nullIntToString(n sql.NullInt64) string {
    if n.Valid {
        return fmt.Sprintf("%d", n.Int64)
    }
    return ""
}

// Helper for nullable strings
func nullStringToString(n sql.NullString) string {
    if n.Valid {
        return n.String
    }
    return ""
}

// Query a TCC DB and return rows as osquery-compatible map slices
func queryTCCDB(dbPath, dbType, username string) ([]map[string]string, error) {
    debugLog("Querying TCC DB: %s (type: %s, user: %s)", dbPath, dbType, username)
    var results []map[string]string

    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        debugLog("Failed to open DB %s: %v", dbPath, err)
        return nil, fmt.Errorf("open TCC db: %w", err)
    }
    defer db.Close()

    rows, err := db.Query(`
        SELECT service, client, client_type, auth_value, auth_reason, auth_version,
               csreq, policy_id, indirect_object_identifier_type,
               indirect_object_identifier, indirect_object_code_identity, flags,
               last_modified
        FROM access
    `)
    if err != nil {
        debugLog("Failed to query DB %s: %v", dbPath, err)
        return nil, fmt.Errorf("query TCC db: %w", err)
    }
    defer rows.Close()

    for rows.Next() {
        var (
            service, client                         string
            clientType, authValue, authReason, authVersion int64
            csreq, indirectObjectCodeIdentity                []byte
            policyID, indirectObjectIdentifier               sql.NullString
            indirectObjectIdentifierType, flags              sql.NullInt64
            lastModified                                     int64
        )

        err := rows.Scan(
            &service, &client, &clientType, &authValue, &authReason, &authVersion,
            &csreq, &policyID, &indirectObjectIdentifierType,
            &indirectObjectIdentifier, &indirectObjectCodeIdentity, &flags,
            &lastModified,
        )
        if err != nil {
            debugLog("Failed to scan row in %s: %v", dbPath, err)
            continue
        }

        results = append(results, map[string]string{
            "type":                            dbType,
            "username":                        username,
            "service":                         service,
            "client":                          client,
            "client_type":                     fmt.Sprintf("%d", clientType),
            "auth_value":                      fmt.Sprintf("%d", authValue),
            "auth_reason":                     fmt.Sprintf("%d", authReason),
            "auth_version":                    fmt.Sprintf("%d", authVersion),
            "csreq":                           bytesToHexString(csreq),
            "policy_id":                       nullStringToString(policyID),
            "indirect_object_identifier_type": nullIntToString(indirectObjectIdentifierType),
            "indirect_object_identifier":      nullStringToString(indirectObjectIdentifier),
            "indirect_object_code_identity":   bytesToHexString(indirectObjectCodeIdentity),
            "flags":                           nullIntToString(flags),
            "last_modified":                   fmt.Sprintf("%d", lastModified),
        })
    }

    if err := rows.Err(); err != nil {
        debugLog("Row error in DB %s: %v", dbPath, err)
        return nil, fmt.Errorf("scan TCC db: %w", err)
    }

    debugLog("Returning %d rows from %s", len(results), dbPath)
    return results, nil
}

// Get list of local users
func userList() ([]*user.User, error) {
    baseDir := "/Users"
    entries, err := os.ReadDir(baseDir)
    if err != nil {
        debugLog("Failed to read user dir %s: %v", baseDir, err)
        return nil, err
    }
    var users []*user.User
    for _, entry := range entries {
        if !entry.IsDir() || entry.Name() == "Shared" {
            continue
        }
        u, err := user.Lookup(entry.Name())
        if err == nil {
            debugLog("Found user: %s (home: %s)", u.Username, u.HomeDir)
            users = append(users, u)
        } else {
            debugLog("Failed to lookup user %s: %v", entry.Name(), err)
        }
    }
    debugLog("Total users found: %d", len(users))
    return users, nil
}

// Table generate callback: gathers system and user TCC.db data
func tccGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
    debugLog("tccGenerate called")

    var results []map[string]string

    sysDB := "/Library/Application Support/com.apple.TCC/TCC.db"
    if _, err := os.Stat(sysDB); err == nil {
        debugLog("System TCC DB found at: %s", sysDB)
        sysRows, err := queryTCCDB(sysDB, "system", "")
        if err != nil {
            debugLog("Error querying system TCC DB: %v", err)
            return nil, fmt.Errorf("system TCC.db error: %w", err)
        }
        results = append(results, sysRows...)
    } else {
        debugLog("System TCC DB not found at: %s", sysDB)
    }

    users, err := userList()
    if err != nil {
        debugLog("Error listing users: %v", err)
        return nil, fmt.Errorf("listing users: %w", err)
    }
    for _, u := range users {
        tccPath := filepath.Join(u.HomeDir, "Library/Application Support/com.apple.TCC/TCC.db")
        if _, err := os.Stat(tccPath); err == nil {
            debugLog("User TCC DB found at: %s", tccPath)
            userRows, err := queryTCCDB(tccPath, "user", u.Username)
            if err != nil {
                debugLog("Error querying user TCC DB %s: %v", tccPath, err)
                continue
            }
            results = append(results, userRows...)
        } else {
            debugLog("User TCC DB not found at: %s", tccPath)
        }
    }

    debugLog("tccGenerate returning %d rows", len(results))
    return results, nil
}

func tccTable() *table.Plugin {
    return table.NewPlugin("macos_tcc", tccColumns, tccGenerate)
}

// Get the osquery extension socket path, for all launch methods
func getSocketPath() string {
    // 1. Check env var
    socket := os.Getenv("OSQUERY_EXTENSION_SOCKET")
    if socket != "" {
        debugLog("Using socket from OSQUERY_EXTENSION_SOCKET: %s", socket)
        return socket
    }
    // 2. Check for --socket or --socket= on the command line
    for i, arg := range os.Args {
        if arg == "--socket" && i+1 < len(os.Args) {
            debugLog("Using socket from --socket: %s", os.Args[i+1])
            return os.Args[i+1]
        }
        if strings.HasPrefix(arg, "--socket=") {
            debugLog("Using socket from --socket=: %s", arg[9:])
            return arg[9:]
        }
    }
    // 3. Fallback
    debugLog("Falling back to default socket path: /var/osquery/osquery.em")
    return "/var/osquery/osquery.em"
}

func main() {
    socketPath := getSocketPath()
    debugLog("Starting osquery extension manager server at socket: %s", socketPath)

    server, err := osquery.NewExtensionManagerServer("macos_tcc", socketPath)
    if err != nil {
        log.Fatalf("Error starting osquery extension: %v", err)
    }

    debugLog("Registering macos_tcc table plugin")
    server.RegisterPlugin(tccTable())
    debugLog("Running osquery extension manager server...")
    server.Run()
}
