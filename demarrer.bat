@echo off
echo ============================================
echo   PhishGuard Togo - Demarrage rapide
echo ============================================
echo.

cd /d "%~dp0"

echo Lancement du serveur...
start "PhishGuard Server" cmd /k "python app.py"

echo Attente du demarrage du serveur (5 secondes)...
timeout /t 5 /nobreak >nul

echo Ouverture du certificat HTTPS dans le navigateur...
start https://localhost:5000

echo.
echo ============================================
echo Si un avertissement de securite apparait dans
echo le navigateur, clique "Avance" puis
echo "Continuer vers localhost".
echo.
echo Ensuite, va sur Gmail et recharge la page
echo (Ctrl+Shift+R).
echo ============================================
echo.
pause
