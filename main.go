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
    `CREATE TABLE IF NOT EXISTS hostgroup (
      "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
      "label" TEXT NOT NULL );`,
    `CREATE TABLE IF NOT EXISTS member (
      "gid" INTEGER NOT NULL,
      "hid" INTEGER NOT NULL );`,
    `CREATE TABLE IF NOT EXISTS tunnel (
      "client" INTEGER NOT NULL,
      "target" INTEGER NOT NULL,
      "isgroup" BOOLEAN NOT NULL );` }

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

func retrieveGroup(db *sql.DB, label string) (*Group, error) {
  stmt, err := db.Prepare(`SELECT * FROM hostgroup WHERE label = ?`)
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

func retrieveAllGroupLabels(db *sql.DB) []string {
  rows, err := db.Query(`SELECT DISTINCT label FROM hostgroup ORDER BY label ASC`)

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
  stmt, err := db.Prepare(`INSERT INTO hostgroup(label) VALUES (?)`)

  if err == nil {
    _, err = stmt.Exec(group.Label)
  }

  return err
}

func delGroup(db *sql.DB, group *Group) error {
  stmt, err := db.Prepare(`DELETE FROM hostgroup WHERE id = ?`)

  if err == nil {
    _, err = stmt.Exec(group.ID)
  }

  return err
}

func getGroupAndHost(db *sql.DB, group, host string) (*Group, *Host) {
  g, _ := retrieveGroup(db, group)
  h, _ := retrieveHost(db, host)
  return g, h
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

func homePage(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintf(w, "ok")
}

func handleRequests() {
  myRouter := mux.NewRouter().StrictSlash(true)
  myRouter.HandleFunc("/", homePage).Methods("GET")
  log.Fatal(http.ListenAndServe(":10000", myRouter))
}

func contains(haystack []string, needle string) bool {
  i := sort.SearchStrings(haystack, needle)
  return i < len(haystack) && haystack[i] == needle
}

func main() {
  if _, err := os.Stat("wgconfig.db"); os.IsNotExist(err) {
    dbFile, err := os.Create("wgconfig.db")
    if err != nil {
      log.Fatal(err.Error())
    }
    dbFile.Close()
  }

  db, _ := sql.Open("sqlite3", "./wgconfig.db");
  defer db.Close()
  createTables(db)

  argLength := len(os.Args[1:])

  if argLength >= 1 {
    switch(os.Args[1]) {
    case "serve":
      fmt.Println("Received directive to serve.")
      handleRequests()

    case "addhost":
      if argLength != 6 {
        log.Fatal("Bad arg count. Expected six (6) args.")
      } else if host, _ := retrieveHost(db, os.Args[2]); host != nil {
        fmt.Println(host)
        log.Fatal("A host with that name already exists.")
      } else {
        host := Host {
          ID: 0,
          Hostname: os.Args[2],
          PublicKey: os.Args[3],
          PublicIP: os.Args[5],
          WireguardIP: os.Args[4],
          WireguardPort: os.Args[5],
        }

        if err := addHost(db, host); err == nil {
          fmt.Println("Added new host.");
        } else {
          log.Fatal(err.Error())
        }
      }

    case "delhost":
      if argLength != 2 {
        log.Fatal("Bad arg count. Expected two (2) args.")
      } else if host, _ := retrieveHost(db, os.Args[2]); host == nil {
        log.Fatal("A host with that name is not known.")
      } else {
        if err := removeHost(db, host); err == nil {
          fmt.Println("Removed host.")
        } else {
          log.Fatal(err.Error())
        }
      }

    case "addgroup":
      if argLength != 2 {
        log.Fatal("Bad arg count. Expected two (2) args.")
      } else if group, _ := retrieveGroup(db, os.Args[2]); group != nil {
        log.Fatal("A group with that label already exists.")
      } else {
        group := Group {
          ID: 0,
          Label: os.Args[2],
        }

        if err := addGroup(db, group); err == nil {
          fmt.Println("Added new group.");
        } else {
          log.Fatal(err.Error())
        }
      }

    case "delgroup":
      if argLength != 2 {
        log.Fatal("Bad arg count. Expected two (2) args.")
      } else if group, _ := retrieveGroup(db, os.Args[2]); group == nil {
        log.Fatal("No group with that label exists currently.")
      } else {
        if err := delGroup(db, group); err == nil {
          fmt.Println("Removed group.")
        } else {
          log.Fatal(err.Error())
        }
      }

    case "addmember":
      if argLength != 3 {
        log.Fatal("Bad arg count. Expected three (3) args.")
      } else if group, host := getGroupAndHost(db, os.Args[3], os.Args[2]); group == nil || host == nil {
        log.Fatal("Either the group or the host could not be found.")
      } else if members := retrieveMembers(db, group); contains(members, host.Hostname) {
        log.Fatal("That host is already a member of the group.")
      } else {
        if err := addMember(db, group, host); err == nil {
          fmt.Println("Added member to group.")
        } else {
          log.Fatal(err.Error())
        }
      }


    case "delmember":
      if argLength != 3 {
        log.Fatal("Bad arg count. Expected three (3) args.")
      } else if group, host := getGroupAndHost(db, os.Args[3], os.Args[2]); group == nil || host == nil {
        log.Fatal("Either the group or the host could not be found.")
      } else if members := retrieveMembers(db, group); !contains(members, host.Hostname) {
        log.Fatal("That host isn't a member of the group.")
      } else {
        if err := removeMember(db, group, host); err == nil {
          fmt.Println("Removed member from group.")
        } else {
          log.Fatal(err.Error())
        }
      }

    case "addtun":

    case "deltun":

    case "getconfig":
      if argLength != 1 {
        log.Fatal("Bad arg count. Expected one (1) arg.")
      } else {
        fmt.Println("Hosts:")
        for _, hostname := range retrieveAllHostnames(db) {
          fmt.Println("- " + hostname)
        }

        fmt.Println("Groups:")
        for _, grouplabel := range retrieveAllGroupLabels(db) {
          fmt.Println("- " + grouplabel)
          group, _ := retrieveGroup(db, grouplabel)
          for _, member := range retrieveMembers(db, group) {
            fmt.Println("  - " + member)
          }
        }
      }

    default:
      fmt.Println("Invalid argument.")
    }
  } else {
    fmt.Println(`Wireguard Configurator Usage
        - serve the RESTful API:      "serve"
        - add a host:                 "addhost <hostname> <pubkey> <wg-ip> <pub-ip> <port>"
        - remove a host:              "delhost <hostname>"
        - add a group:                "addgroup <group>"
        - remove a group:             "delgroup <group>"
        - add a host to a group:      "addmember <host> <group>"
        - remove a host from a group: "delmember <host> <group>"
        - add a tunnel:               "link <host> <host|group>"
        - remove a tunnel:            "unlink <host> <host|group>"
        - get the current config:     "getconfig"`)
  }
}
