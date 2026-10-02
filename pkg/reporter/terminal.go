package reporter

import (
	"fmt"
	"github.com/seraphimdeck/daraku/pkg/models"
)

func PrintTerminal(findings []models.Finding) {
	fmt.Println("\n=======================================================")
	fmt.Println("             daraku - REPORT SUMMARY          ")
	fmt.Println("=======================================================")
	fmt.Printf("Total Temuan: %d\n\n", len(findings))

	if len(findings) == 0 {
		fmt.Println("[+] Tidak ditemukan kerentanan.")
		return
	}

	for i, f := range findings {
		fmt.Printf("[%d] [%s] %s\n", i+1, f.Severity, f.Title)
		fmt.Printf("    ID          : %s\n", f.ID)
		fmt.Printf("    Kategori    : %s\n", f.Category)
		fmt.Printf("    Entitas     : %s\n", f.AffectedEntity)
		fmt.Printf("    Deskripsi   : %s\n", f.Description)
		fmt.Printf("    Remediasi   : %s\n", f.Remediation)
		fmt.Println("-------------------------------------------------------")
	}
}
