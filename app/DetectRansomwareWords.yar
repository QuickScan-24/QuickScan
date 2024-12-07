rule DetectRansomwareInExe
{
    meta:
        description = "Detects common ransomware phrases in executable files"
        author = "Your Name"
        date = "2024-11-30"

    strings:
        $keyword1 = "encrypted" nocase
        $keyword2 = "your files have been encrypted" nocase
        $keyword3 = "AES" nocase
        $keyword4 = "RSA" nocase
        $keyword5 = "encryption key" nocase
        $keyword6 = "decryptor" nocase
        $keyword7 = "crypto-locker" nocase
        $keyword8 = "readme" nocase
        $keyword9 = ".locked" nocase
        $keyword10 = ".decrypt" nocase
        $keyword11 = ".help" nocase
        $keyword12 = ".key" nocase
        $keyword13 = /All your files have been (locked|encrypted)/ nocase
        $keyword14 = /Your system has been hacked/ nocase
        $keyword15 = /Send Bitcoin to this address/ nocase
        $keyword16 = /How to recover your files/ nocase
        $keyword17 = /Recover your data/ nocase
        $keyword18 = /Do not delete this file/ nocase
        $keyword19 = /Your files will be deleted in \d+ hours/ nocase
        $keyword20 = /Do not try to decrypt files manually/ nocase
        $keyword21 = /Do not contact law enforcement/ nocase
        $keyword22 = /Your ID: [a-zA-Z0-9]+/ nocase

    condition:
        any of them
}
