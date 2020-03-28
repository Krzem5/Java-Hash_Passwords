echo off
echo NUL>_.class&&del /s /f /q *.class
cls
javac com/krzem/hash_passwords/Main.java&&java com/krzem/hash_passwords/Main
start /min cmd /c "echo NUL>_.class&&del /s /f /q *.class"