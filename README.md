# Libro

Aplikasi web sederhana (Node.js + Express + frontend statis): login/daftar akun, daftar menu/event, manajemen user & event untuk admin.
Data disimpan di file JSON (`users.json`, `events.json`, `purchases.json`).

## Menjalankan di komputer sendiri

```
npm install
npm run dev      # mode demo (token reset password ikut dikembalikan di response)
```

Buka http://localhost:3000. Untuk mode normal (seperti server asli) pakai `npm start`.

## Membuat admin pertama

Pendaftaran lewat halaman web **selalu** menghasilkan user biasa. Untuk menjadikan seseorang admin:

1. Daftar dulu lewat halaman "Create account".
2. Di terminal (di folder projek / di server), jalankan:

```
node make-admin.js username_anda
node make-admin.js --list        # melihat daftar user
```

Setelah itu admin lain bisa dijadikan admin dari menu User Management.

## Aturan input

- Email harus lengkap (`nama@domain.tld`); Gmail wajib `@gmail.com`.
- Username 3-30 karakter: huruf, angka, titik, garis bawah, strip (tanpa spasi dan `@`).
- Password 6-72 karakter.
- Login bisa memakai username atau email.

## Variabel environment

| Variabel | Fungsi |
| --- | --- |
| `PORT` | Port server (default 3000). Biasanya diisi otomatis oleh hosting. |
| `DATA_DIR` | Folder penyimpanan data. **Arahkan ke disk permanen** di hosting, mis. `/var/data`. |
| `SESSION_SECRET` | Kunci penanda tangan cookie login (string acak panjang). Jika kosong, dibuat otomatis di `DATA_DIR/.session-secret`. |
| `NODE_ENV` | Isi `production` di server asli (menyembunyikan detail error dan log request). |
| `TRUST_PROXY` | Isi `1` jika berada di belakang Nginx/Cloudflare/Railway agar IP dan HTTPS terbaca benar. |
| `DEMO_RESET` | `1` = kembalikan token reset password di response (**hanya untuk lokal**). |

## Deploy ke VPS (Ubuntu) - ringkas

```
# 1. pasang Node.js 20+ lalu ambil kode
git clone https://github.com/USERNAME/Libro.git && cd Libro
npm install --omit=dev

# 2. siapkan folder data di luar folder kode
sudo mkdir -p /var/libro-data && sudo chown $USER /var/libro-data

# 3. jalankan dengan pm2 supaya tetap hidup
sudo npm i -g pm2
DATA_DIR=/var/libro-data NODE_ENV=production TRUST_PROXY=1 SESSION_SECRET=$(openssl rand -hex 32) \
  pm2 start server.js --name libro --update-env
pm2 save && pm2 startup

# 4. jadikan diri sendiri admin (setelah daftar lewat web)
DATA_DIR=/var/libro-data node make-admin.js username_anda
```

Lalu pasang **Nginx** sebagai reverse proxy ke `localhost:3000` dan aktifkan **HTTPS** (Certbot/Let's Encrypt).
Jika `SESSION_SECRET` diisi manual, simpan nilainya (misalnya di file `.env` yang tidak di-commit) supaya tidak berubah saat restart.

Jangan deploy ke layanan serverless (Vercel/Netlify): penyimpanan file JSON tidak bisa ditulis di sana.
Di tier gratis Render, file hilang setiap restart; pakai layanan dengan volume/disk permanen.

## Keamanan yang sudah diterapkan

- Hanya `index.html` dan folder `assets/` yang bisa diakses publik (file seperti `users.json` dan `server.js` tidak bisa diunduh).
- Login memakai cookie sesi bertanda tangan (`HttpOnly`, `SameSite=Lax`, `Secure` saat HTTPS), berlaku 7 hari. Mengganti password mengeluarkan semua perangkat lain.
- Endpoint admin (`/users*`, `/events/add|update|delete`) hanya untuk admin; pembelian & riwayat butuh login, dan user hanya melihat/membatalkan pesanannya sendiri.
- Field `role` dari pendaftaran diabaikan; token reset password tidak dikirim ke penelepon dan disimpan sebagai hash.
- Pembatasan percobaan login/daftar/reset (anti tebak password), validasi input, hash password bcrypt.
- Data dari user di-escape sebelum ditampilkan (anti XSS), ekspor CSV aman dari formula injection.
- Penulisan file JSON atomik dengan backup `.bak` otomatis.

## Keterbatasan yang perlu diketahui

- **Belum ada pengiriman email**, jadi fitur lupa password hanya mencetak token di log server (untuk diteruskan pemilik server). Untuk produksi sungguhan, hubungkan layanan email.
- Penyimpanan file JSON cocok untuk demo dan pengguna sedikit, bukan untuk banyak pengguna bersamaan. Langkah berikutnya: pindah ke database (mis. SQLite/PostgreSQL).
- Halaman riwayat order di frontend masih memakai `localStorage` browser, belum tersambung ke `/purchases` di server.
- `test-add-event.js` kini mendapat 401 karena `/events/add` butuh login admin (itu memang perilaku yang benar).
