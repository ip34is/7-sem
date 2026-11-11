@echo off
rem Usage: run.bat Task1Conveyor  (class name from the src folder)
rem The PetriObjModelPaint editor jar is used as the library; set PETRI_JAR if it is elsewhere.
chcp 65001 >nul
if "%PETRI_JAR%"=="" set "PETRI_JAR=%USERPROFILE%\Downloads\PetriObjModelPaint\app\petri-swing-ui-windows.jar"
java -Dstdout.encoding=UTF-8 -cp "%PETRI_JAR%" "%~dp0src\%1.java"
