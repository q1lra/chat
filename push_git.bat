@echo off
cls

git config user.email "q1lra@proton.me"
git config user.name "q1lra"

git init
git add .
git commit -m "init"
git branch -M main
git remote add origin https://github.com/q1lra/chat.git
git push -u origin main
