# SQLID-URAC 
## (SQL Injection Detector using Regex & Aho-Corasick)
SQL Injection Detector using Regex and Aho-Corasick algorithm for preventing SQL Injection attack.

## Daftar Isi

- [Instalasi](#instalasi)
- [Penggunaan](#penggunaan)
- [Kontribusi](#kontribusi)
- [Kredit](#kredit)
- [Kontak](#kontak)

## Instalasi

Langkah-langkah untuk menginstal dan menjalankan proyek ini:

1.  Pastikan PHP telah terinstal di sistem Anda. Anda dapat memeriksa versi PHP dengan menjalankan perintah berikut di terminal atau command prompt: `php -v`
2.  Jika PHP belum terinstal, silakan instal versi terbaru dari situs resmi PHP atau menggunakan manajer paket seperti Homebrew (untuk macOS) atau Chocolatey (untuk Windows).
3.  Pastikan Composer telah terinstal di sistem Anda. Anda dapat memeriksa versi Composer dengan menjalankan perintah berikut di terminal atau command prompt: `composer -v`
4.  Jika Composer belum terinstal, ikuti panduan instalasi resmi di *getcomposer.org*.
5.  Setelah Anda memiliki PHP dan Composer yang terinstal, buka terminal atau command prompt dan arahkan ke direktori proyek Anda.
6.  Jalankan perintah berikut untuk menginstal dependensi proyek menggunakan Composer: `composer install` | Perintah ini akan membaca file composer.json dan mengunduh serta menginstal semua dependensi yang didefinisikan dalam file tersebut.
7.  Setelah selesai, Anda dapat menjalankan proyek PHP Anda melalui server pengembangan PHP seperti Apache atau Nginx. Catatan: Pastikan Anda mengikuti instruksi konfigurasi server yang sesuai dengan sistem operasi Anda untuk mengarahkan server ke direktori proyek Anda.
8.  Apabila anda telah berhasil menginstall composer, pada command prompt atau terminal jalankan perintah: `composer require satuduasatu/sqlid`
9.  setelah anda berhasil menginstall package program ini, anda hanya perlu untuk require atau include detector.php pada setiap form pada program anda dengan cara `require_once 'sqlid/src/detector.php';` atau `include_once 'sqlid/src/detector.php';`.
10. SQLID telah berhasil dipasang pada program anda.

## Penggunaan

1. Digunakan untuk meningkatkan keamanan pada form pada program anda hanya dengan melakukan include atau require pada 'detector.php'
2. Melalui kombinasi pengecekan ganda oleh regex dan aho-corasick mencegah terjadinya penyerangan melalui pendeteksian dan pemberhentian aksi dari form yang diserang.
3. Pencatatan Log Request dan response untuk analisis percobaan penyerangan atas program anda.

## Kontribusi

Jika Anda ingin berkontribusi pada proyek ini, Anda dapat mengikuti langkah-langkah berikut:

1. Fork repositori ini.
2. Buat branch baru: `git checkout -b fitur-baru`.
3. Lakukan perubahan yang diinginkan dan commit: `git commit -m 'Menambahkan fitur baru'`.
4. Push ke branch yang baru dibuat: `git push origin fitur-baru`.
5. Ajukan permintaan penarikan (pull request).

## Kredit

Terima kasih kepada Institut Teknologi Del sebagai Fasilitator project ini, dan terima kasih tim satuduasatu atas kontribusinya pada proyek ini.

## Kontak

Anda dapat menghubungi saya melalui [timsatuduasatu@gmail.com].


