#!/usr/bin/env bash
# Quick local setup (no Docker) for Auto-Doc Redactor - React edition.
set -e

echo "==> Setting up backend..."
cd backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_lg
cp -n .env.example .env || true
cd ..

echo "==> Setting up frontend (React)..."
cd frontend
npm install
cd ..

echo "==> Done!"
echo "Start backend:  cd backend && source venv/bin/activate && uvicorn app.main:app --reload"
echo "Start frontend: cd frontend && npm run dev"
