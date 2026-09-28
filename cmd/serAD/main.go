package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
  "time"
	"os"
	"strings"

	"github.com/seraphimdeck/serAD/pkg/detectors"
	"github.com/seraphimdeck/serAD/pkg/gatekeeper"
	"github.com/seraphimdeck/serAD/pkg/http"
	"github.com/seraphimdeck/serAD/pkg/ldap"
	"github.com/seraphimdeck/serAD/pkg/models"
	"github.com/seraphimdeck/serAD/pkg/reporter"
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
const Version= "1.1.3"
const Banner = `
 ██████╗███████╗██████╗  █████╗ ██████╗ 
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗
███████╗█████╗  ██████╔╝███████║██║  ██║
╚════██║██╔══╝  ██╔══██╗██╔══██║██║  ██║
███████║███████╗██║  ██║██║  ██║██████╔╝
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  V` + Version + `
 Active Directory & AD CS Audit Engine
`

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

	printShortUsage := func() {
		fmt.Printf("%s%s%s\n", Cyan, Banner, Reset)
		fmt.Printf("%sGunakan:%s ./serAD -target <IP> -user <USER> -pass <PASS> [opsi]\n\n", Bold+Yellow, Reset)
		fmt.Printf("%sFlag:%s\n", Bold, Reset)
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Printf("  -%s\n", f.Name)
		})

		fmt.Printf("Gunakan %s./serAD --help%s untuk melihat keterangan lengkap.\n\n", Bold+Yellow, Reset)
	}

	printFullUsage := func() {
		fmt.Printf("%s%s%s\n", Cyan, Banner, Reset)
		fmt.Printf("%sGunakan:%s ./serAD -target <IP> -user <USER> -pass <PASS> [opsi]\n\n", Bold+Yellow, Reset)
		fmt.Printf("%sOpsi Keterangan:%s\n", Bold, Reset)
		flag.PrintDefaults()
	}

	for _, arg := range os.Args[1:] {
		if arg == "--help" || arg == "-h" || arg == "-help" {
			printFullUsage()
			os.Exit(0)
		}
	}

  showVersion := flag.Bool("version", false, "Tampilkan versi")
	flag.Usage = printShortUsage
	flag.Parse()

  if *showVersion {
    fmt.Printf("serAD v%s\n", Version)
    os.Exit(0)
  }
	if *targetIP == "" || *bindDN == "" || (*password == "" && !*passwordStdin) {
		flag.Usage()
		os.Exit(0)
	}


	if *passwordStdin {
		if *password != "" {
			log.Fatal("gunakan salah satu -pass atau -password-stdin")
		}
		reader := bufio.NewReader(os.Stdin)
		value, err := reader.ReadString('\n')
		if err != nil && len(value) == 0 {
			log.Fatalf("gagal membaca password dari stdin: %v", err)
		}
		*password = strings.TrimRight(value, "\r\n")
		if *password == "" {
			log.Fatal("password dari stdin kosong")
		}
	}

	if *insecureTLS && !*useTLS {
		log.Fatal("-insecure-tls hanya valid bersama -tls")
	}


	fmt.Printf("%s%s%s\n", Cyan, Banner, Reset)

  hostname, _ := os.Hostname()
  meta := models.AuditMetadata{
    Timestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
    Hostname:  hostname,
    Operator:  *bindDN,
    TargetDC:  *targetIP,
    Port:      *port,
  }

  
	fmt.Printf("%s[*] Memulai Pre-Audit Gatekeeper Safety Checks...%s\n", Bold+Blue, Reset)
	gk := gatekeeper.New(*targetIP, *port)
	if err := gk.Validate(); err != nil {
		log.Fatalf("%s[FATAL] Gatekeeper Validation GAGAL: %v%s", Bold+Red, err, Reset)
	}
	fmt.Printf("%s[+] Gatekeeper Check PASS: Target valid, privat, dan berada dalam segmen LAN lokal.%s\n", Green, Reset)

	fmt.Printf("%s[*] Menghubungi LDAP Server...%s\n", Bold+Blue, Reset)
	if !*useTLS {
		fmt.Printf("%s[WARN] LDAP bind menggunakan koneksi plaintext. Gunakan -tls.%s\n", Yellow, Reset)
	}
	client, err := ldap.NewClient(*targetIP, *port, *useTLS, *insecureTLS, *tlsServerName, *bindDN, *password)
	if err != nil {
		log.Fatalf("%s[FATAL] Koneksi LDAP GAGAL: %v%s", Bold+Red, err, Reset)
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

	fmt.Printf("%s[*] Menjalankan HTTP ESC8 Web Enrollment Probe...%s\n", Bold+Blue, Reset)
	probe := http.NewProbeClient()
	var probeFindings []models.Finding
	for i := range cas {
		finding, err := probe.CheckESC8(&cas[i])
		if err != nil {
			log.Printf("%s[WARN] ESC8 Probe error pada %s: %v%s", Yellow, cas[i].DNSHostName, err, Reset)
		}
		if finding != nil {
			log.Printf("%s[!] ESC8 Terdeteksi pada CA %s%s", Bold+Red, cas[i].Name, Reset)
			probeFindings = append(probeFindings, *finding)
		}
	}

	fmt.Printf("%s[*] Mengeksekusi Detection Engine...%s\n", Bold+Blue, Reset)
	engine := detectors.NewEngine(users, computers, templates, cas)
	findings := engine.RunAll()
	findings = append(findings, probeFindings...)

	fmt.Printf("%s[*] Mencetak Laporan...%s\n", Bold+Blue, Reset)
	reporter.PrintTerminal(findings)

	if err := reporter.ExportMarkdown(*outMD, findings, meta); err != nil {
		log.Printf("%s[WARN] Gagal membuat laporan Markdown: %v%s", Yellow, err, Reset)
	} else {
		fmt.Printf("%s[+] Laporan Markdown tersimpan: %s%s\n", Green, *outMD, Reset)
	}

	if err := reporter.ExportJSON(*outJSON, findings, meta); err != nil {
		log.Printf("%s[WARN] Gagal membuat laporan JSON: %v%s", Yellow, err, Reset)
	} else {
		fmt.Printf("%s[+] Laporan JSON tersimpan: %s%s\n", Green, *outJSON, Reset)
	}

	fmt.Printf("%s[+] Proses Audit Selesai.%s\n", Bold+Green, Reset)
}
