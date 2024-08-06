package bt

import (
	"database/sql"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

var db *sql.DB

type Site struct {
	Id      int
	Name    string
	Path    string
	Status  string
	Index   string
	Ps      string
	AddTime string
}
type Domain struct {
	Id      int
	Pid     int
	Name    string
	Port    int
	AddTime string
}

func InitDb(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	return nil
}

func QuerySite(name string) (*Site, error) {
	stmt, err := db.Prepare("select id,name from sites where name=?")
	if err != nil {
		return nil, err
	}
	row := stmt.QueryRow(name)
	var s Site
	err = row.Scan(&s.Id, &s.Name)
	if err != nil {
		return nil, err
	}
	return &s, nil

}

func SaveSite(site *Site) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	err = addSite(tx, site)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	err = addDomain(tx, site.Name, site.Id)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	_ = tx.Commit()
	return nil
}

func addSite(tx *sql.Tx, site *Site) error {
	stmt, err := tx.Prepare("insert into sites(`name`,`path`,`status`,`ps`,`addtime`)values(?,?,?,?,?)")
	if err != nil {
		return err
	}
	result, err := stmt.Exec(site.Name, site.Path, site.Status, site.Ps, site.AddTime)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	site.Id = int(id)
	return nil
}
func addDomain(tx *sql.Tx, name string, pid int) error {
	d := &Domain{Name: name, Pid: pid, Port: 443, AddTime: time.Now().Format("2006-01-02 15:04:05")}
	d2 := &Domain{Name: "*." + name, Pid: pid, Port: 443, AddTime: time.Now().Format("2006-01-02 15:04:05")}
	stmt, err := tx.Prepare("insert into domain(`pid`,`name`,`port`,`addtime`)values(?,?,?,?),(?,?,?,?)")
	if err != nil {
		return err
	}
	result, err := stmt.Exec(d.Pid, d.Name, d.Port, d.AddTime, d2.Pid, d2.Name, d2.Port, d2.AddTime)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	d.Id = int(id)
	return nil
}
