#!/usr/bin/env node
'use strict';
// Menjadikan user sebagai admin dari terminal server.
//   node make-admin.js <username>     -> jadikan admin
//   node make-admin.js --list         -> tampilkan daftar user
// Akun harus sudah terdaftar lewat halaman "Create account" terlebih dahulu.
// Kalau server memakai DATA_DIR, jalankan dengan variabel yang sama, mis:
//   DATA_DIR=/var/data node make-admin.js budi

const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
const USERS_FILE = path.join(DATA_DIR, 'users.json');

function load() {
    if (!fs.existsSync(USERS_FILE)) {
        console.error('File users.json tidak ditemukan di', DATA_DIR);
        process.exit(1);
    }
    const raw = fs.readFileSync(USERS_FILE, 'utf8').replace(/^\uFEFF/, '').trim();
    return raw ? JSON.parse(raw) : [];
}

const arg = process.argv[2];
if (!arg) {
    console.log('Pemakaian: node make-admin.js <username>   atau   node make-admin.js --list');
    process.exit(1);
}

const users = load();

if (arg === '--list') {
    users.forEach(u => console.log(`${String(u.id).padEnd(4)} ${String(u.username).padEnd(20)} ${String(u.role || 'user').padEnd(6)} ${u.email}`));
    process.exit(0);
}

const user = users.find(u => u && String(u.username).toLowerCase() === arg.toLowerCase());
if (!user) {
    console.error(`User "${arg}" tidak ditemukan. Daftar dulu lewat halaman Create account.`);
    process.exit(1);
}
user.role = 'admin';
fs.copyFileSync(USERS_FILE, USERS_FILE + '.bak');
fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
console.log(`OK: ${user.username} sekarang admin.`);
