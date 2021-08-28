/*
 * Copyright (c) 2021 Caleb L. Power. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for specific language governing permissions and
 * limitations under the License.
 */

package main

import (
  "fmt"
  "log"
  "os"
  "sort"
  "strings"
  "database/sql"
  "net/http"
  "github.com/gorilla/mux"
  _ "github.com/mattn/go-sqlite3"
)

type Host struct {
  ID uint64
  Hostname string
  PublicKey string
  PublicIP string
  WireguardIP string
  WireguardPort string
}

type Group struct {
  ID uint64
  Label string
}

type Tunnel struct {
  HostID uint64
  TargetID uint64
  IsGroup bool
}

var (
  hosts []Host
  groups map[Group][]Host
  tunnel map[Host][]Tunnel
  db *sql.DB
)

func createTables(db *sql.DB) {

  mkTblSQL := []string {
    `CREATE TABLE IF NOT EXISTS host (
      "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
      "name" TEXT NOT NULL,
      "pubkey" TEXT NOT NULL,
      "pubip" TEXT,
      "wgip" TEXT NOT NULL,
      "port" INTEGER );`,

    `CREATE TABLE IF NOT EXISTS host_group (
      "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
      "label" TEXT NOT NULL );`,

    `CREATE TABLE IF NOT EXISTS member (
      "gid" INTEGER NOT NULL,
      "hid" INTEGER NOT NULL,
      CONSTRAINT fk_gid
        FOREIGN KEY (gid)
        REFERENCES host_group(id)
        ON DELETE CASCADE,
      CONSTRAINT fk_hid
        FOREIGN KEY (hid)
        REFERENCES host(id)
        ON DELETE CASCADE );`,

    `CREATE TABLE IF NOT EXISTS tunnel_hh (
      "hid_a" INTEGER NOT NULL,
      "hid_b" INTEGER NOT NULL,
      CONSTRAINT fk_hid_a
        FOREIGN KEY (hid_a)
        REFERENCES host(id)
        ON DELETE CASCADE,
      CONSTRAINT fk_hid_b
        FOREIGN KEY (hid_b)
        REFERENCES host(id)
        ON DELETE CASCADE );`,

    `CREATE TABLE IF NOT EXISTS tunnel_gg (
      "gid_a" INTEGER NOT NULL,
      "gid_b" INTEGER NOT NULL,
      CONSTRAINT fk_gid_a
        FOREIGN KEY (gid_a)
        REFERENCES host_group(id)
        ON DELETE CASCADE,
      CONSTRAINT fk_gid_b
        FOREIGN KEY (gid_b)
        REFERENCES host_group(id)
        ON DELETE CASCADE );`,

    `CREATE TABLE IF NOT EXISTS tunnel_gh (
      "hid" INTEGER NOT NULL,
      "gid" INTEGER NOT NULL,
      CONSTRAINT fk_hid
        FOREIGN KEY (hid)
        REFERENCES host(id)
        ON DELETE CASCADE,
      CONSTRAINT fk_gid
        FOREIGN KEY (gid)
        REFERENCES host_group(id)
        ON DELETE CASCADE );`,

    `CREATE TABLE IF NOT EXISTS allowed_ip (
      "addr" TEXT NOT NULL );` }

  for _, element := range mkTblSQL {
    statement, err := db.Prepare(element)
    if err != nil {
      log.Fatal(err.Error())
    }
    statement.Exec()
  }
}

func retrieveHost(db *sql.DB, hostname string) (*Host, error) {
  stmt, err := db.Prepare(`SELECT * FROM host WHERE name = ?`)
  if err != nil {
    log.Fatalln(err.Error())
  }

  var host Host
  err = stmt.QueryRow(hostname).Scan(&host.ID, &host.Hostname, &host.PublicKey, &host.PublicIP, &host.WireguardIP, &host.WireguardPort)
  if err != nil {
    return nil, err
  }

  return &host, err
}

func retrieveAllHostnames(db *sql.DB) []string {
  rows, err := db.Query(`SELECT DISTINCT name FROM host ORDER BY name ASC`)

  if err != nil {
    log.Fatalln(err.Error())
  }

  defer rows.Close()

  var hostnames []string

  for rows.Next() {
    var hostname string
    err = rows.Scan(&hostname)

    if err != nil {
      log.Fatalln(err.Error())
    }

    hostnames = append(hostnames, hostname)
  }

  return hostnames
}

func addHost(db *sql.DB, host Host) error {
  stmt, err := db.Prepare(`INSERT INTO host(name, pubkey, pubip, wgip, port) VALUES (?, ?, ?, ?, ?)`)
  if err != nil {
    return err
  }

  _, err = stmt.Exec(host.Hostname, host.PublicKey, host.PublicIP, host.WireguardIP, host.WireguardPort)
  if err != nil {
    return err
  }

  return nil
}

func removeHost(db *sql.DB, host *Host) error {
  stmt, err := db.Prepare(`DELETE FROM host WHERE id = ?`)
  if err != nil {
    return err
  }

  _, err = stmt.Exec(host.ID)
  if err != nil {
    return err
  }

  return nil
}

func ipIsAllowed(db *sql.DB, addr string) bool {
  stmt, err := db.Prepare(`SELECT * FROM allowed_ip WHERE addr = ?`)
  if err == nil {
    err = stmt.QueryRow(addr).Scan(&addr)
    if err == nil {
      return true
    } else if err != sql.ErrNoRows {
      log.Fatalln(err.Error())
    }
  } else {
    log.Fatalln(err.Error())
  }

  return false
}

func allowIP(db *sql.DB, addr string) error {
  stmt, err := db.Prepare(`INSERT INTO allowed_ip(addr) VALUES (?)`)
  if err != nil {
    return err
  }

  _, err = stmt.Exec(addr)
  if err != nil {
    return err
  }

  return nil
}

func revokeIP(db *sql.DB, addr string) error {
  stmt, err := db.Prepare(`DELETE FROM allowed_ip WHERE addr = ?`)
  if err != nil {
    return err
  }

  _, err = stmt.Exec(addr)
  if err != nil {
    return err
  }

  return nil
}

func retrieveGroup(db *sql.DB, label string) (*Group, error) {
  stmt, err := db.Prepare(`SELECT * FROM host_group WHERE label = ?`)
  if err != nil {
    log.Fatalln(err.Error())
  }

  var group Group
  err = stmt.QueryRow(label).Scan(&group.ID, &group.Label)
  if err != nil {
    return nil, err
  }

  return &group, err
}

func retrieveAllowedIPs(db *sql.DB) []string {
  rows, err := db.Query(`SELECT DISTINCT addr FROM allowed_ip ORDER BY addr ASC`)

  if err != nil {
    log.Fatalln(err.Error())
  }

  defer rows.Close()

  var addrs []string

  for rows.Next() {
    var addr string
    err = rows.Scan(&addr)

    if err != nil {
      log.Fatalln(err.Error())
    }

    addrs = append(addrs, addr)
  }

  return addrs
}

func retrieveAllGroupLabels(db *sql.DB) []string {
  rows, err := db.Query(`SELECT DISTINCT label FROM host_group ORDER BY label ASC`)

  if err != nil {
    log.Fatalln(err.Error())
  }

  defer rows.Close()

  var labels []string

  for rows.Next() {
    var label string
    err = rows.Scan(&label)

    if err != nil {
      log.Fatalln(err.Error())
    }

    labels = append(labels, label)
  }

  return labels
}

func addGroup(db *sql.DB, group Group) error {
  stmt, err := db.Prepare(`INSERT INTO host_group(label) VALUES (?)`)

  if err == nil {
    _, err = stmt.Exec(group.Label)
  }

  return err
}

func delGroup(db *sql.DB, group *Group) error {
  stmt, err := db.Prepare(`DELETE FROM host_group WHERE id = ?`)

  if err == nil {
    _, err = stmt.Exec(group.ID)
  }

  return err
}

func grabGroupAndHost(db *sql.DB, group, host string) (*Group, *Host) {
  g, _ := retrieveGroup(db, group)
  h, _ := retrieveHost(db, host)
  return g, h
}

func grabTwoHosts(db *sql.DB, hostA, hostB string) (*Host, *Host) {
  hA, _ := retrieveHost(db, hostA)
  hB, _ := retrieveHost(db, hostB)
  return hA, hB
}

func grabTwoGroups(db *sql.DB, groupA, groupB string) (*Group, *Group) {
  gA, _ := retrieveGroup(db, groupA)
  gB, _ := retrieveGroup(db, groupB)
  return gA, gB
}

func retrieveMembers(db *sql.DB, group *Group) []string {
  stmt, err := db.Prepare(`SELECT host.name FROM host
      INNER JOIN member ON host.id = member.hid
      WHERE member.gid = ?`)
  if err != nil {
    log.Fatalln(err.Error())
  }

  defer stmt.Close()

  rows, err := stmt.Query(group.ID)
  if err != nil {
    log.Fatalln(err.Error())
  }

  defer rows.Close()

  var members []string

  for rows.Next() {
    var member string
    err = rows.Scan(&member)

    if err != nil {
      log.Fatalln(err.Error())
    }

    members = append(members, member)
  }

  return members
}

func addMember(db *sql.DB, group *Group, host *Host) error {
  stmt, err := db.Prepare(`INSERT INTO member(gid, hid) VALUES (?, ?)`)

  if err == nil {
    _, err = stmt.Exec(group.ID, host.ID)
  }

  return err
}

func removeMember(db *sql.DB, group *Group, host *Host) error {
  stmt, err := db.Prepare(`DELETE FROM member WHERE gid = ? AND hid = ?`)

  if err == nil {
    _, err = stmt.Exec(group.ID, host.ID)
  }

  return err
}

func existsHHTun(db *sql.DB, hostA, hostB *Host) bool {
  stmtA, errA := db.Prepare(`SELECT * FROM tunnel_hh WHERE hid_a = ? AND hid_b = ?`)
  if errA == nil {
    errA = stmtA.QueryRow(hostA.ID, hostB.ID).Scan(&hostA.ID, &hostB.ID)
    if errA == nil {
      return true
    } else if errA != sql.ErrNoRows {
      log.Fatalln(errA.Error())
    }
  } else {
    log.Fatalln(errA.Error())
  }

  return false
}

func existsGGTun(db *sql.DB, groupA, groupB *Group) bool {
  stmtA, errA := db.Prepare(`SELECT * FROM tunnel_gg WHERE gid_a = ? AND gid_b = ?`)
  if errA == nil {
    errA = stmtA.QueryRow(groupA.ID, groupB.ID).Scan(&groupA.ID, &groupB.ID)
    if errA == nil {
      return true
    } else if errA != sql.ErrNoRows {
      log.Fatalln(errA.Error())
    }
  } else {
    log.Fatalln(errA.Error())
  }

  return false
}

func existsHGTun(db *sql.DB, host *Host, group *Group) bool {
  stmt, err := db.Prepare(`SELECT * FROM tunnel_gh WHERE gid = ? AND hid = ?`)
  if err == nil {
    err = stmt.QueryRow(group.ID, host.ID).Scan(&host.ID, &group.ID)
    if err == nil {
      return true
    } else if err != sql.ErrNoRows {
      log.Fatalln(err.Error())
    }
  } else {
    log.Fatalln(err.Error())
  }

  return false
}

func dedupe(sA []string) []string {
  var deduped []string

  for i := 0; i < len(sA); i++ {
    if len(deduped) == 0 || deduped[len(deduped) - 1] != sA[i] {
      deduped = append(deduped, sA[i])
    }
  }

  return deduped
}

func delelem(sA []string, target string) []string {
  var scrubbed []string

  for i := 0; i < len(sA); i++ {
    if sA[i] != target {
      scrubbed = append(scrubbed, sA[i])
    }
  }

  return scrubbed
}

func merge(sA, sB []string) []string {
  var merged []string

  for len(sA) > 0 && len(sB) > 0 {
    if sA[0] <= sB[0] {
      merged = append(merged, sA[0])
      sA = sA[1:]
    } else {
      merged = append(merged, sB[0])
      sB = sB[1:]
    }
  }

  merged = append(merged, sA...)
  merged = append(merged, sB...)
  sA = sA[:0]
  sB = sB[:0]

  return merged
}

func getHostTuns(db *sql.DB, host *Host) ([]string, []string) {
  ghStmt, ghErr := db.Prepare(`SELECT host_group.label FROM host_group
      INNER JOIN tunnel_gh ON host_group.id = tunnel_gh.gid
      WHERE tunnel_gh.hid = ?
      ORDER BY host_group.label ASC`)

  if ghErr != nil {
    log.Fatalln(ghErr.Error())
  }

  defer ghStmt.Close()

  ghRows, ghErr := ghStmt.Query(host.ID)
  if(ghErr != nil) {
    log.Fatalln(ghErr.Error())
  }

  defer ghRows.Close()

  var groups []string

  for ghRows.Next() {
    var group string
    err := ghRows.Scan(&group)

    if err != nil {
      log.Fatalln(err.Error())
    }

    groups = append(groups, group)
  }

  hhStmtA, hhErrA := db.Prepare(`SELECT host.name FROM host
      INNER JOIN tunnel_hh ON host.id = tunnel_hh.hid_a
      WHERE tunnel_hh.hid_b = ?
      ORDER BY host.name ASC`)

  if hhErrA != nil {
    log.Fatalln(hhErrA.Error())
  }

  defer hhStmtA.Close()

  hhRowsA, hhErrA := hhStmtA.Query(host.ID)
  if(hhErrA != nil) {
    log.Fatalln(hhErrA.Error())
  }

  defer hhRowsA.Close()

  var hostsA []string

  for hhRowsA.Next() {
    var hostname string
    err := hhRowsA.Scan(&hostname)

    if err != nil {
      log.Fatalln(err.Error())
    }

    hostsA = append(hostsA, hostname)
  }

  hhStmtB, hhErrB := db.Prepare(`SELECT host.name FROM host
      INNER JOIN tunnel_hh ON host.id = tunnel_hh.hid_b
      WHERE tunnel_hh.hid_a = ?
      ORDER BY host.name ASC`)

  if hhErrB != nil {
    log.Fatalln(hhErrB.Error())
  }

  defer hhStmtB.Close()

  hhRowsB, hhErrB := hhStmtB.Query(host.ID)
  if(hhErrB != nil) {
    log.Fatalln(hhErrB.Error())
  }

  defer hhRowsB.Close()

  var hostsB []string

  for hhRowsB.Next() {
    var hostname string
    err := hhRowsB.Scan(&hostname)

    if err != nil {
      log.Fatalln(err.Error())
    }

    if(hostname != host.Hostname) {
      hostsB = append(hostsB, hostname)
    }
  }

  return merge(hostsA, hostsB), groups
}

func getGroupTuns(db *sql.DB, group *Group) ([]string, []string) {
  ghStmt, ghErr := db.Prepare(`SELECT host.name FROM host
      INNER JOIN tunnel_gh ON host.id = tunnel_gh.hid
      WHERE tunnel_gh.gid = ?
      ORDER BY host.name ASC`)

  if ghErr != nil {
    log.Fatalln(ghErr.Error())
  }

  defer ghStmt.Close()

  ghRows, ghErr := ghStmt.Query(group.ID)
  if(ghErr != nil) {
    log.Fatalln(ghErr.Error())
  }

  defer ghRows.Close()

  var hosts []string

  for ghRows.Next() {
    var host string
    err := ghRows.Scan(&host)

    if err != nil {
      log.Fatalln(err.Error())
    }

    hosts = append(hosts, host)
  }

  ggStmtA, ggErrA := db.Prepare(`SELECT host_group.label FROM host_group
      INNER JOIN tunnel_gg ON host_group.id = tunnel_gg.gid_a
      WHERE tunnel_gg.gid_b = ?
      ORDER BY host_group.label ASC`)

  if ggErrA != nil {
    log.Fatalln(ggErrA.Error())
  }

  defer ggStmtA.Close()

  ggRowsA, ggErrA := ggStmtA.Query(group.ID)
  if(ggErrA != nil) {
    log.Fatalln(ggErrA.Error())
  }

  defer ggRowsA.Close()

  var groupsA []string

  for ggRowsA.Next() {
    var label string
    err := ggRowsA.Scan(&label)

    if err != nil {
      log.Fatalln(err.Error())
    }

    groupsA = append(groupsA, label)
  }

  ggStmtB, ggErrB := db.Prepare(`SELECT host_group.label FROM host_group
      INNER JOIN tunnel_gg ON host_group.id = tunnel_gg.gid_b
      WHERE tunnel_gg.gid_a = ?
      ORDER BY host_group.label ASC`)

  if ggErrB != nil {
    log.Fatalln(ggErrB.Error())
  }

  defer ggStmtB.Close()

  ggRowsB, ggErrB := ggStmtB.Query(group.ID)
  if(ggErrB != nil) {
    log.Fatalln(ggErrB.Error())
  }

  defer ggRowsB.Close()

  var groupsB []string

  for ggRowsB.Next() {
    var label string
    err := ggRowsB.Scan(&label)

    if err != nil {
      log.Fatalln(err.Error())
    }

    if(label != group.Label) {
      groupsB = append(groupsB, label)
    }
  }

  return hosts, merge(groupsA, groupsB)
}

func linkHHTun(db *sql.DB, hostA, hostB *Host) error {
  stmt, err := db.Prepare(`INSERT INTO tunnel_hh(hid_a, hid_b) VALUES (?, ?)`)

  if err == nil {
    _, err = stmt.Exec(hostA.ID, hostB.ID)
  }

  return err
}

func linkGGTun(db *sql.DB, groupA, groupB *Group) error {
  stmt, err := db.Prepare(`INSERT INTO tunnel_gg(gid_a, gid_b) VALUES (?, ?)`)

  if err == nil {
    _, err = stmt.Exec(groupA.ID, groupB.ID)
  }

  return err
}

func linkHGTun(db *sql.DB, host *Host, group *Group) error {
  stmt, err := db.Prepare(`INSERT INTO tunnel_gh(gid, hid) VALUES (?, ?)`)

  if err == nil {
    _, err = stmt.Exec(group.ID, host.ID)
  }

  return err
}

func unlinkHHTun(db *sql.DB, hostA, hostB *Host) error {
  stmt, err := db.Prepare(`DELETE FROM tunnel_hh WHERE hid_a = ? AND hid_b = ?`)

  if err == nil {
    _, err = stmt.Exec(hostA.ID, hostB.ID)
  }

  return err
}

func unlinkGGTun(db *sql.DB, groupA, groupB *Group) error {
  stmt, err := db.Prepare(`DELETE FROM tunnel_gg WHERE gid_a = ? AND gid_b = ?`)

  if err == nil {
    _, err = stmt.Exec(groupA.ID, groupB.ID)
  }

  return err
}

func unlinkHGTun(db *sql.DB, host *Host, group *Group) error {
  stmt, err := db.Prepare(`DELETE FROM tunnel_gh WHERE gid = ? AND hid = ?`)

  if err == nil {
    _, err = stmt.Exec(group.ID, host.ID)
  }

  return err
}

func routeIndex(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintf(w, "ok\n")
}

func routeHostConfig(w http.ResponseWriter, r *http.Request) {
  var clientIPs []string
  xRealIP := r.Header.Get("X-Real-Ip")
  if xRealIP != "" {
    clientIPs = append(clientIPs, xRealIP)
  }
  xForwardedFor := r.Header.Get("X-Forwarded-For")
  for _, ip := range strings.Split(xForwardedFor, ", ") {
    if ip != "" {
      clientIPs = append(clientIPs, ip)
    }
  }
  clientIPs = append(clientIPs, strings.Split(r.RemoteAddr, ":")[0])

  badIP := false

  for _, clientIP := range clientIPs {
    //fmt.Println("Checking client IP " + clientIP)
    if !ipIsAllowed(db, clientIP) {
      fmt.Println("Bad IP = " + clientIP)
      badIP = true
      break
    }
  }

  if badIP {
    fmt.Fprintf(w, "nope")
  } else {
    vars := mux.Vars(r)
    hostname := vars["host"]
    if host, err := retrieveHost(db, hostname); err != nil {
      fmt.Fprintf(w, "bad\n")
    } else {
      fmt.Fprintf(w, "[Interface]\n")
      fmt.Fprintf(w, "PrivateKey = {{ PRIVATE_KEY }}\n")
      fmt.Fprintf(w, "Address = " + host.WireguardIP + "\n")
      if host.WireguardPort == "" {
        fmt.Fprintf(w, "DNS = {{ DNS }}\n")
      } else {
        fmt.Fprintf(w, "ListenPort = " + host.WireguardPort + "\n")
      }

      hostTuns, groupTuns := getHostTuns(db, host)
      for _, groupLabel := range groupTuns {
        group, _ := retrieveGroup(db, groupLabel)
        hostTuns = merge(hostTuns, retrieveMembers(db, group))
      }

      hostTuns = dedupe(hostTuns)
      hostTuns = delelem(hostTuns, hostname)

      for _, peerName := range hostTuns {
        peer, _ := retrieveHost(db, peerName)
        fmt.Fprintf(w, "\n[Peer]\n")
        fmt.Fprintf(w, "PublicKey = " + peer.PublicKey + "\n")
        fmt.Fprintf(w, "AllowedIPs = " + peer.WireguardIP + "/32\n")
        if peer.PublicIP != "" {
          fmt.Fprintf(w, "Endpoint = " + peer.PublicIP + ":" + peer.WireguardPort + "\n")
          fmt.Fprintf(w, "PersistentKeepalive = 20\n")
        }
      }
    }

  }
}

func handleRequests() {
  myRouter := mux.NewRouter().StrictSlash(true)
  myRouter.HandleFunc("/", routeIndex).Methods("GET")
  myRouter.HandleFunc("/hosts/{host}", routeHostConfig).Methods("GET")
  log.Fatal(http.ListenAndServe(":10000", myRouter))
}

func contains(haystack []string, needle string) bool {
  i := sort.SearchStrings(haystack, needle)
  return i < len(haystack) && haystack[i] == needle
}

func ternary(q bool, t, f string) string {
  if q {
    return t
  }
  return f
}

func main() {
  argLength := len(os.Args[1:])

  if argLength >= 2 {
    dbFilename := os.Args[1] + ".db"
    if _, err := os.Stat(dbFilename); os.IsNotExist(err) {
      dbFile, err := os.Create(dbFilename)
      if err != nil {
        log.Fatal(err.Error())
      }
      dbFile.Close()
    }

    db, _ = sql.Open("sqlite3", "./" + dbFilename);
    defer db.Close()
    createTables(db)

    switch(os.Args[2]) {
    case "serve":
      fmt.Println("Received directive to serve.")
      handleRequests()

    case "addhost":
      if argLength != 5 && argLength != 7 {
        log.Fatal("Bad arg count. Expected five (5) or seven (7) args.")
      } else if host, _ := retrieveHost(db, os.Args[3]); host != nil {
        log.Fatal("A host with that name already exists.")
      } else {
        host := Host {
          ID: 0,
          Hostname: os.Args[3],
          PublicKey: os.Args[4],
          PublicIP: ternary(argLength == 7, os.Args[argLength - 1], ""),
          WireguardIP: os.Args[5],
          WireguardPort: ternary(argLength == 7, os.Args[argLength], "") }

        if err := addHost(db, host); err == nil {
          fmt.Println("Added new host.");
        } else {
          log.Fatal(err.Error())
        }
      }

    case "delhost":
      if argLength != 3 {
        log.Fatal("Bad arg count. Expected three (3) args.")
      } else if host, _ := retrieveHost(db, os.Args[3]); host == nil {
        log.Fatal("A host with that name is not known.")
      } else if err := removeHost(db, host); err == nil {
        fmt.Println("Removed host.")
      } else {
        log.Fatal(err.Error())
      }

    case "addgroup":
      if argLength != 3 {
        log.Fatal("Bad arg count. Expected three (3) args.")
      } else if group, _ := retrieveGroup(db, os.Args[3]); group != nil {
        log.Fatal("A group with that label already exists.")
      } else {
        group := Group {
          ID: 0,
          Label: os.Args[3],
        }

        if err := addGroup(db, group); err == nil {
          fmt.Println("Added new group.");
        } else {
          log.Fatal(err.Error())
        }
      }

    case "delgroup":
      if argLength != 3 {
        log.Fatal("Bad arg count. Expected three (3) args.")
      } else if group, _ := retrieveGroup(db, os.Args[3]); group == nil {
        log.Fatal("No group with that label exists currently.")
      } else if err := delGroup(db, group); err == nil {
        fmt.Println("Removed group.")
      } else {
        log.Fatal(err.Error())
      }

    case "addmember":
      if argLength != 4 {
        log.Fatal("Bad arg count. Expected four (4) args.")
      } else if group, host := grabGroupAndHost(db, os.Args[4], os.Args[3]); group == nil || host == nil {
        log.Fatal("Either the group or the host could not be found.")
      } else if members := retrieveMembers(db, group); contains(members, host.Hostname) {
        log.Fatal("That host is already a member of the group.")
      } else if err := addMember(db, group, host); err == nil {
        fmt.Println("Added member to group.")
      } else {
        log.Fatal(err.Error())
      }


    case "delmember":
      if argLength != 4 {
        log.Fatal("Bad arg count. Expected four (4) args.")
      } else if group, host := grabGroupAndHost(db, os.Args[4], os.Args[3]); group == nil || host == nil {
        log.Fatal("Either the group or the host could not be found.")
      } else if members := retrieveMembers(db, group); !contains(members, host.Hostname) {
        log.Fatal("That host isn't a member of the group.")
      } else if err := removeMember(db, group, host); err == nil {
        fmt.Println("Removed member from group.")
      } else {
        log.Fatal(err.Error())
      }

    case "hhlink":
      if argLength != 4 {
        log.Fatal("Bad arg count. Expected four (4) args.")
      } else if hostA, hostB := grabTwoHosts(db, os.Args[3], os.Args[4]); hostA == nil || hostB == nil {
        log.Fatal("One or both of the specified hosts doesn't exist.")
      } else if existsHHTun(db, hostA, hostB) || existsHHTun(db, hostB, hostA) {
        log.Fatal("Those hosts are already linked.")
      } else if err := linkHHTun(db, hostA, hostB); err == nil {
        fmt.Println("Successfully linked hosts.")
      } else {
        log.Fatal(err.Error())
      }

    case "hhunlink":
      if argLength != 4 {
        log.Fatal("Bad arg count. Expected four (4) args.")
      } else if hostA, hostB := grabTwoHosts(db, os.Args[3], os.Args[4]); hostA == nil || hostB == nil {
        log.Fatal("One or both of the specified hosts doesn't exist.")
      } else if !existsHHTun(db, hostA, hostB) && !existsHHTun(db, hostB, hostA) {
        log.Fatal("Those hosts are not currently linked.")
      } else if err := unlinkHHTun(db, hostA, hostB); err == nil {
        fmt.Println("Successfully unlinked hosts.")
      } else {
        log.Fatal(err.Error())
      }

    case "gglink":
      if argLength != 4 {
        log.Fatal("Bad arg count. Expected four (4) args.")
      } else if groupA, groupB := grabTwoGroups(db, os.Args[3], os.Args[4]); groupA == nil || groupB == nil {
        log.Fatal("One or both of the specified groups doesn't exist.")
      } else if existsGGTun(db, groupA, groupB) || existsGGTun(db, groupB, groupA) {
        log.Fatal("Those groups are already linked.")
      } else if err := linkGGTun(db, groupA, groupB); err == nil {
        fmt.Println("Successfully linked groups.")
      } else {
        log.Fatal(err.Error())
      }

    case "ggunlink":
      if argLength != 4 {
        log.Fatal("Bad arg count. Expected four (4) args.")
      } else if groupA, groupB := grabTwoGroups(db, os.Args[3], os.Args[4]); groupA == nil || groupB == nil {
        log.Fatal("One or both of the specified groups doesn't exist.")
      } else if !existsGGTun(db, groupA, groupB) && !existsGGTun(db, groupB, groupA) {
        log.Fatal("Those groups are not currently linked.")
      } else if err := unlinkGGTun(db, groupA, groupB); err == nil {
        fmt.Println("Successfully unlinked groups.")
      } else {
        log.Fatal(err.Error())
      }

    case "hglink":
      if argLength != 4 {
        log.Fatal("Bad arg count. Expected four (4) args.")
      } else if group, host := grabGroupAndHost(db, os.Args[4], os.Args[3]); group == nil || host == nil {
        log.Fatal("A specified host or group is missing.")
      } else if existsHGTun(db, host, group) {
        log.Fatal("The specified host and group are already linked.")
      } else if err := linkHGTun(db, host, group); err == nil {
        fmt.Println("Successfully linked host and group.")
      } else {
        log.Fatal(err.Error())
      }

    case "hgunlink":
      if argLength != 4 {
        log.Fatal("Bad arg count. Expected four (4) args.")
      } else if group, host := grabGroupAndHost(db, os.Args[4], os.Args[3]); group == nil || host == nil {
        log.Fatal("A specified host or group is missing.")
      } else if !existsHGTun(db, host, group) {
        log.Fatal("The specified host and group are not currently linked.")
      } else if err := unlinkHGTun(db, host, group); err == nil {
        fmt.Println("Successfully unlinked host and group.")
      } else {
        log.Fatal(err.Error())
      }

    case "allowip":
      if argLength != 3 {
        log.Fatal("Bad arg count. Expected three (3) args.")
      } else if ipIsAllowed(db, os.Args[3]) {
        log.Fatal("That IP is already allowed.")
      } else if err := allowIP(db, os.Args[3]); err == nil {
        fmt.Println("Successfully allowed access by that IP address.")
      } else {
        log.Fatal(err.Error())
      }

    case "revokeip":
      if argLength != 3 {
        log.Fatal("Bad arg count. Expected three (3) args.")
      } else if !ipIsAllowed(db, os.Args[3]) {
        log.Fatal("That IP is already not allowed.")
      } else if err := revokeIP(db, os.Args[3]); err == nil {
        fmt.Println("Successfully revoked access by that IP address.")
      } else {
        log.Fatal(err.Error())
      }

    case "getconfig":
      if argLength != 2 {
        log.Fatal("Bad arg count. Expected two (2) args.")
      } else {
        fmt.Println("Hosts:")
        for _, hostname := range retrieveAllHostnames(db) {
          host, _ := retrieveHost(db, hostname)
          fmt.Println("- " + hostname + " (" + host.WireguardIP + ")")
          if host.PublicIP != "" {
            fmt.Println("  - Endpoint: " + host.PublicIP + ":" + host.WireguardPort)
          }
          fmt.Println("  - Pubkey: " + host.PublicKey)
          fmt.Println("  - Tunnels:")
          hostTuns, groupTuns := getHostTuns(db, host)
          for _, hostTun := range hostTuns {
            fmt.Println("    - " + hostTun + " (host)")
          }
          for _, groupTun := range groupTuns {
            fmt.Println("    - " + groupTun + " (group)")
          }
        }

        fmt.Println("\nGroups:")
        for _, grouplabel := range retrieveAllGroupLabels(db) {
          fmt.Println("- " + grouplabel)
          fmt.Println("  - Members:")
          group, _ := retrieveGroup(db, grouplabel)
          for _, member := range retrieveMembers(db, group) {
            fmt.Println("    - " + member)
          }
          fmt.Println("  - Tunnels:")
          hostTuns, groupTuns := getGroupTuns(db, group)
          for _, hostTun := range hostTuns {
            fmt.Println("    - " + hostTun + " (host)")
          }
          for _, groupTun := range groupTuns {
            fmt.Println("    - " + groupTun + " (group)")
          }
        }

        fmt.Println("\nAllowed IPs Addresses:")
        for _, addr := range retrieveAllowedIPs(db) {
          fmt.Println("- " + addr)
        }

      }

    default:
      fmt.Println("Invalid argument.")
    }
  } else {
    fmt.Println(`
  Wireguard Configurator Usage.
  Copyright (c) 2021 Caleb L. Power.
  All rights reserved.

  - serve the RESTful API.......... "<env> serve"

  - add a host..................... "<env> addhost <host> <pubkey> <wg-ip> <pub-ip> <port>"
  - remove a host.................. "<env> delhost <host>"

  - add a group.................... "<env> addgroup <env> <group>"
  - remove a group................. "<env> delgroup <group>"

  - add a host to a group.......... "<env> addmember <host> <group>"
  - remove a host from a group..... "<env> delmember <host> <group>"

  - add a host->host tunnel........ "<env> hhlink <host> <host>"
  - remove a host->host tunnel..... "<env> hhunlink <host> <host>"

  - add a host->group tunnel....... "<env> hglink <host> <group>"
  - remove a host->group tunnel.... "<env> hgunlink <host> <group>"

  - add a group->group tunnel...... "<env> gglink <group> <group>"
  - remove a group->group tunnel... "<env> ggunlink <group> <group>"

  - add an IP to the allowlist .... "<env> allowip <ip>"
  - revoke access from an IP ...... "<env> revokeip <ip>"

  - get the current config......... "<env> getconfig"
      `)
  }
}
