package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"github.com/seraphimdeck/daraku/pkg/detectors"
	"github.com/seraphimdeck/daraku/pkg/gatekeeper"
	"github.com/seraphimdeck/daraku/pkg/ldap"
	"github.com/seraphimdeck/daraku/pkg/models"
	"github.com/seraphimdeck/daraku/pkg/reporter"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

const Version = "1.1.8"
const Banner = `
  ___   _   ___   _   _  _ _   _ 
 |   \ /_\ | _ \ /_\ | |/ / | | |
 | |) / _ \|   // _ \| ' <| |_| |
 |___/_/ \_\_|_/_/ \_\_|\_\\___/ V` + Version + `
 Active Directory & AD CS Audit Tool
`

type Config struct {
	TargetIP      string
	Port          int
	UseTLS        bool
	InsecureTLS   bool
	TLSServerName string
	BindDN        string
	Password      string
	OutMD         string
	OutJSON       string
}

func main() {
	targetIP := flag.String("target", "", "IP / FQDN Target Domain Controller")
	port := flag.Int("port", 389, "Port LDAP / LDAPS")
	useTLS := flag.Bool("tls", false, "Gunakan koneksi LDAPS (TLS)")
	insecureTLS := flag.Bool("insecure-tls", false, "Abaikan verifikasi sertifikat TLS")
	tlsServerName := flag.String("tls-server-name", "", "Server Name Indication (SNI) untuk TLS")
	bindDN := flag.String("user", "", "Bind DN atau Username LDAP")
	password := flag.String("pass", "", "Password otentikasi LDAP")
	passwordStdin := flag.Bool("password-stdin", false, "Baca password dari Stdin")
	outMD := flag.String("out-md", "audit_report.md", "Path file output laporan Markdown")
	outJSON := flag.String("out-json", "audit_report.json", "Path file output laporan JSON")
	showVersion := flag.Bool("version", false, "Tampilkan versi")

	flag.Parse()

	if *showVersion {
		fmt.Printf("daraku v%s\n", Version)
		os.Exit(0)
	}

	cfg := Config{
		TargetIP:      *targetIP,
		Port:          *port,
		UseTLS:        *useTLS,
		InsecureTLS:   *insecureTLS,
		TLSServerName: *tlsServerName,
		BindDN:        *bindDN,
		Password:      *password,
		OutMD:         *outMD,
		OutJSON:       *outJSON,
	}

	if *passwordStdin {
		reader := bufio.NewReader(os.Stdin)
		value, err := reader.ReadString('\n')
		if err != nil && len(value) == 0 {
			log.Fatalf("gagal membaca password dari stdin: %v", err)
		}
		cfg.Password = strings.TrimRight(value, "\r\n")
	}

	if cfg.TargetIP != "" && cfg.BindDN != "" && cfg.Password != "" {
		executeAudit(cfg)
		return
	}

	startConsole(cfg)
}

func showLoading() {
	frames := []string{"[ / ]", "[ - ]", "[ \\ ]", "[ | ]"}
	
	for i := 0; i < 70; i++ {
		fmt.Printf("\r%s[*] Initializing %s%s", Cyan, frames[i%len(frames)], Reset)
		time.Sleep(90 * time.Millisecond)
	}
	
	fmt.Printf("\r%s[+] daraku loaded successfully! %s\n\n", Green, Reset)
}


func startConsole(cfg Config) {
	fmt.Printf("%s%s%s\n", Cyan, Banner, Reset)
  showLoading()
	fmt.Printf("%s[*] Ketik 'help' atau 'show options'.%s\n\n", Bold+Yellow, Reset)

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%sdaraku%s (%sAD/CS%s) > ", Bold+Red, Reset, Bold+Cyan, Reset)
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		args := strings.Fields(input)
		cmd := strings.ToLower(args[0])

		switch cmd {
		case "exit", "quit":
			fmt.Println("Keluar dari console.")
			return

		case "help", "?":
			printConsoleHelp()

		case "show":
			if len(args) > 1 && strings.ToLower(args[1]) == "options" {
				printOptions(cfg)
			} else {
				fmt.Println("Penggunaan: show options")
			}

		case "set":
			if len(args) >= 3 {
				setOption(&cfg, strings.ToLower(args[1]), strings.Join(args[2:], " "))
			} else {
				fmt.Println("Penggunaan: set <option> <value>")
			}

		case "run", "exploit", "audit":
			if cfg.TargetIP == "" || cfg.BindDN == "" || cfg.Password == "" {
				fmt.Printf("%s[!] Error! Set target, user, dan pass terlebih dahulu.%s\n", Bold+Red, Reset)
			} else {
				executeAudit(cfg)
			}

		case "banner":
			fmt.Printf("%s%s%s\n", Cyan, Banner, Reset)

		default:
			fmt.Printf("Error: %s. Ketik 'help' untuk bantuan.\n", cmd)
		}
	}
}

func printConsoleHelp() {
	fmt.Printf("\n%sPerintah:%s\n", Bold, Reset)
	fmt.Println("  show options       Menampilkan konfigurasi parameter saat ini")
	fmt.Println("  set <opt> <val>    Mengatur nilai parameter (contoh: set target 192.168.1.10)")
	fmt.Println("  run / audit        Mulai mengeksekusi modul audit AD & AD CS")
	fmt.Println("  banner             Tampilkan ulang banner daraku")
	fmt.Println("  help / ?           Tampilkan menu bantuan ini")
	fmt.Println("  exit / quit        Keluar dari konsol")
	fmt.Println()
}

func printOptions(cfg Config) {
	fmt.Printf("\n%sKonfigurasi:%s\n", Bold+Yellow, Reset)
	fmt.Printf("  %-15s %-25s %s\n", "Option", "Value", "Description")
	fmt.Printf("  %-15s %-25s %s\n", "------", "-----", "-----------")
	fmt.Printf("  %-15s %-25s %s\n", "target", cfg.TargetIP, "IP / FQDN Target Domain Controller (Wajib)")
	fmt.Printf("  %-15s %-25s %s\n", "user", cfg.BindDN, "Bind DN / Username LDAP (Wajib)")
	fmt.Printf("  %-15s %-25s %s\n", "pass", cfg.Password, "Password otentikasi LDAP (Wajib)")
	fmt.Printf("  %-15s %-25d %s\n", "port", cfg.Port, "Port LDAP / LDAPS (Default: 389)")
	fmt.Printf("  %-15s %-25t %s\n", "tls", cfg.UseTLS, "Gunakan koneksi LDAPS TLS")
	fmt.Printf("  %-15s %-25t %s\n", "insecure-tls", cfg.InsecureTLS, "Abaikan verifikasi sertifikat TLS")
	fmt.Printf("  %-15s %-25s %s\n", "out-md", cfg.OutMD, "Path file output laporan Markdown")
	fmt.Printf("  %-15s %-25s %s\n", "out-json", cfg.OutJSON, "Path file output laporan JSON")
	fmt.Println()
}

func setOption(cfg *Config, opt string, val string) {
	switch opt {
	case "target":
		cfg.TargetIP = val
		fmt.Printf("target => %s\n", val)
	case "user":
		cfg.BindDN = val
		fmt.Printf("user => %s\n", val)
	case "pass":
		cfg.Password = val
		fmt.Printf("pass => %s\n", val)
	case "port":
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Port = p
			fmt.Printf("port => %d\n", p)
		} else {
			fmt.Println("[!] Nilai port harus berupa angka")
		}
	case "tls":
		cfg.UseTLS = strings.ToLower(val) == "true" || val == "1"
		fmt.Printf("tls => %t\n", cfg.UseTLS)
	case "insecure-tls":
		cfg.InsecureTLS = strings.ToLower(val) == "true" || val == "1"
		fmt.Printf("insecure-tls => %t\n", cfg.InsecureTLS)
	case "out-md":
		cfg.OutMD = val
		fmt.Printf("out-md => %s\n", val)
	case "out-json":
		cfg.OutJSON = val
		fmt.Printf("out-json => %s\n", val)
	default:
		fmt.Printf("[!] Error: %s. Gunakan 'show options'.\n", opt)
	}
}

func executeAudit(cfg Config) {
	if cfg.InsecureTLS && !cfg.UseTLS {
		log.Println("[WARN] -insecure-tls hanya valid bersama -tls")
	}

	hostname, _ := os.Hostname()
	meta := models.AuditMetadata{
		Timestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
		Hostname:  hostname,
		Operator:  cfg.BindDN,
		TargetDC:  cfg.TargetIP,
		Port:      cfg.Port,
	}

	fmt.Printf("%s[*] Memulai Pre-Audit Gatekeeper Safety Checks...%s\n", Bold+Blue, Reset)
	gk := gatekeeper.New(cfg.TargetIP, cfg.Port)
	if err := gk.Validate(); err != nil {
		fmt.Printf("%s[FATAL] Gatekeeper Validation GAGAL: %v%s\n", Bold+Red, err, Reset)
		return
	}
	fmt.Printf("%s[+] Gatekeeper Check PASS: Target valid, privat, dan berada dalam segmen LAN lokal.%s\n", Green, Reset)

	fmt.Printf("%s[*] Menghubungi LDAP Server...%s\n", Bold+Blue, Reset)
	if !cfg.UseTLS {
		fmt.Printf("%s[WARN] LDAP bind menggunakan koneksi plaintext. Pertimbangkan penggunaan TLS.%s\n", Yellow, Reset)
	}
	client, err := ldap.NewClient(cfg.TargetIP, cfg.Port, cfg.UseTLS, cfg.InsecureTLS, cfg.TLSServerName, cfg.BindDN, cfg.Password)
	if err != nil {
		fmt.Printf("%s[FATAL] Koneksi LDAP GAGAL: %v%s\n", Bold+Red, err, Reset)
		return
	}
	defer client.Close()
	fmt.Printf("%s[+] Terhubung ke LDAP (BaseDN: %s)%s\n", Green, client.BaseDN, Reset)

	fmt.Printf("%s[*] Mengumpulkan data PKI & Active Directory Domain...%s\n", Bold+Blue, Reset)
	templates, cas, err := client.HarvestPKI()
	if err != nil {
		log.Printf("%s[WARN] Gagal mengambil data PKI: %v%s", Yellow, err, Reset)
	}

	users, computers, err := client.HarvestDomain()
	if err != nil {
		log.Printf("%s[WARN] Gagal mengambil data Domain Users/Computers: %v%s", Yellow, err, Reset)
	}

	fmt.Printf("%s[*] Mengeksekusi Detection Engine...%s\n", Bold+Blue, Reset)
	engine := detectors.NewEngine(users, computers, templates, cas)
	findings := engine.RunAll()

	fmt.Printf("%s[*] Mencetak Laporan...%s\n", Bold+Blue, Reset)
	reporter.PrintTerminal(findings)

	if err := reporter.ExportMarkdown(cfg.OutMD, findings, meta); err != nil {
		log.Printf("%s[WARN] Gagal membuat laporan Markdown: %v%s", Yellow, err, Reset)
	} else {
		fmt.Printf("%s[+] Laporan Markdown tersimpan: %s%s\n", Green, cfg.OutMD, Reset)
	}

	if err := reporter.ExportJSON(cfg.OutJSON, findings, meta); err != nil {
		log.Printf("%s[WARN] Gagal membuat laporan JSON: %v%s", Yellow, err, Reset)
	} else {
		fmt.Printf("%s[+] Laporan JSON tersimpan: %s%s\n", Green, cfg.OutJSON, Reset)
	}

	fmt.Printf("%s[+] Proses Audit Selesai.%s\n\n", Bold+Green, Reset)
}
