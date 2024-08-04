package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func CreateNonExistingFolder(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0o700)
	} else if err != nil {
		return err
	}
	return nil
}
func GenerateNginxConf(nginxConfTpl, btVhostDir, domain, crtFile, keyFile string) error {
	rp := strings.NewReplacer("{domain}", domain, "{crt}", crtFile, "{key}", keyFile)
	nginxConf := rp.Replace(nginxConfTpl)
	nginxConfName := fmt.Sprintf("%s.conf", domain)
	if err := CreateNonExistingFolder(btVhostDir); err != nil {
		return err
	}
	err := os.WriteFile(filepath.Join(btVhostDir, nginxConfName), []byte(nginxConf), os.ModePerm)
	if err != nil {
		return err
	}

	return nil

}
