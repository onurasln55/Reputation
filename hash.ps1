function Get-VT-Hash-Reputation {
    param (
        [string]$hash,
        [string]$api
    )
    try {
        $url = "https://www.virustotal.com/api/v3/files/$hash"
        $headers = @{
            "Accept" = "application/json"
            "x-apikey" = $api
        }
        $response = Invoke-RestMethod -Uri $url -Headers $headers
        $malicious = $response.data.attributes.last_analysis_stats.malicious
        $scan_date = $response.data.attributes.last_analysis_date
        $md5 = $response.data.attributes.md5
        $scan_id = $response.data.id
        $scan_date = [System.DateTimeOffset]::FromUnixTimeSeconds($scan_date).DateTime.ToString('HH:mm:ss dd-MM-yyyy')
        $scan_link = "https://www.virustotal.com/gui/file/$scan_id"
        return $malicious, $scan_date, $md5, $scan_link
    } catch {
        Write-Host "Hata oluştu: $($_.Exception.Message)"
        return $null, $null, $null, $null
    }
}

function Get-File-Path {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    $openFileDialog.Filter = "Text Files (*.txt)|*.txt"
    $openFileDialog.Title = "Lütfen dosya seçin"
    $result = $openFileDialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $openFileDialog.FileName
    } else {
        Write-Host "Dosya seçilmedi veya geçerli değil."
        return $null
    }
}

function Process-FromFile {
    param (
        [string]$api,
        [string]$filePath
    )
    try {
        $data = Get-Content -Path $filePath
        $outputFilePath = $filePath -replace '\.txt$', '_sonuc.txt'  # Sonuçların yazılacağı dosya yolunu tanımla
        foreach ($hash in $data) {
            $hash = $hash.Trim()
            if ($hash -match '^[0-9a-fA-F]{64}$') {
                $malicious, $scan_date, $md5, $scan_link = Get-VT-Hash-Reputation -hash $hash -api $api
                if ($malicious -ne $null) {
                    $output = "$hash, $malicious, $scan_date, $md5, $scan_link"
                    
                    # Sonuç dosyasını kontrol et ve yoksa oluştur
                    if (-not (Test-Path $outputFilePath)) {
                        New-Item -Path $outputFilePath -ItemType File | Out-Null
                    }
                    
                    Add-Content -Path $outputFilePath -Value $output  # Sonuçları dosyaya yaz
                }
            }
        }
    } catch {
        Write-Host "Dosya okuma hatası: $($_.Exception.Message)"
    }
}

try {
    # API anahtarınızı buraya girin
    $api_key = ""

    # Dosya yolunu kullanıcıdan seçin
    $filePath = Get-File-Path
    if ($filePath -ne $null) {
        Process-FromFile -api $api_key -filePath $filePath
    }
} catch {
    Write-Host "Bir hata oluştu: $($_.Exception.Message)"
}
