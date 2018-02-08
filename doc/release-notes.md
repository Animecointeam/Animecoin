(note: this is a temporary file, to be added-to by anybody, and deleted at
release time)

Fee Policy changes
------------------

The default fee for low-priority transactions is lowered from 0.0005 BTC 
(for each 1,000 bytes in the transaction; an average transaction is
about 500 bytes) to 0.0001 BTC.

Payments (transaction outputs) of 0.543 times the minimum relay fee
(0.00005430 BTC) are now considered 'non-standard', because storing them
costs the network more than they are worth and spending them will usually
cost their owner more in transaction fees than they are worth.

Non-standard transactions are not relayed across the network, are not included
in blocks by most miners, and will not show up in your wallet until they are
included in a block.

The default fee policy can be overridden using the -mintxfee and -minrelaytxfee
command-line options, but note that we intend to replace the hard-coded fees
with code that automatically calculates and suggests appropriate fees in the
0.9 release and note that if you set a fee policy significantly different from
the rest of the network your transactions may never confirm.

Perubahan Kebijakan Biaya
------------------

Biaya default untuk transaksi dengan prioritas rendah diturunkan dari 0,0005 BTC
(untuk setiap 1.000 byte dalam transaksi; transaksi rata-rata adalah
sekitar 500 byte) sampai 0.0001 BTC.

Pembayaran (output transaksi) sebesar 0,543 kali biaya relay minimum
(0.00005430 BTC) sekarang dianggap 'non-standar', karena menyimpannya
Biaya jaringan lebih dari yang mereka layak dan menghabiskan mereka biasanya
biaya pemilik mereka lebih dalam biaya transaksi dari mereka layak.

Transaksi non-standar tidak disampaikan di seluruh jaringan, tidak termasuk
di blok oleh kebanyakan penambang, dan tidak akan muncul di dompet Anda sampai mereka berada
termasuk dalam satu blok

Kebijakan biaya default dapat diganti menggunakan -mintxfee dan -minrelaytxfee
opsi baris perintah, tapi perhatikan bahwa kami bermaksud mengganti biaya kode keras
dengan kode yang secara otomatis menghitung dan menyarankan biaya yang sesuai di
0,9 rilis dan perhatikan bahwa jika Anda menetapkan kebijakan biaya berbeda secara signifikan
sisa jaringan transaksi Anda mungkin tidak pernah mengkonfirmasi.

Bitcoin-Qt changes
------------------

- New icon and splash screen
- Improve reporting of synchronization process
- Remove hardcoded fee recommendations
- Improve metadata of executable on MacOSX and Windows
- Move export button to individual tabs instead of toolbar
- Add "send coins" command to context menu in address book
- Add "copy txid" command to copy transaction IDs from transaction overview
- Save & restore window size and position when showing & hiding window
- New translations: Arabic (ar), Bosnian (bs), Catalan (ca), Welsh (cy), Esperanto (eo), Interlingua (la), Latvian (lv) and many improvements to current translations

MacOSX:

- OSX support for click-to-pay (bitcoin:) links
- Fix GUI disappearing problem on MacOSX (issue #1522)

Linux/Unix:

- Copy addresses to middle-mouse-button clipboard

Perubahan Bitcoin-Qt
------------------

- Ikon baru dan layar splash
- Meningkatkan pelaporan proses sinkronisasi
- Hapus rekomendasi biaya hardcoded
- Meningkatkan metadata dari executable pada MacOSX dan Windows
- Pindahkan tombol ekspor ke tab individual dan bukan toolbar
- Tambahkan "kirim koin" ke menu konteks di buku alamat
- Tambahkan perintah "copy txid" untuk menyalin ID transaksi dari gambaran transaksi
- Menyimpan & mengembalikan ukuran dan posisi jendela saat menampilkan & menyembunyikan jendela
- Terjemahan baru: bahasa Arab (ar), bahasa Bosnia (bs), bahasa Katalan (ca), bahasa Welsh (cy), bahasa Esperanto (eo), interlingua (la), bahasa latin (lv) dan banyak perbaikan terjemahan saat ini

MacOSX:

- Dukungan OSX untuk klik untuk membayar (bitcoin :) links
- Perbaiki masalah GUI yang hilang di MacOSX (masalah # 1522)

Linux / Unix:

- Salin alamat ke clipboard tombol tengah mouse

Command-line options
--------------------

* `-walletnotify` will call a command on receiving transactions that affect the wallet.
* `-alertnotify` will call a command on receiving an alert from the network.
* `-par` now takes a negative number, to leave a certain amount of cores free.

Opsi baris perintah
--------------------

* `-walletnotify` akan memanggil perintah untuk menerima transaksi yang mempengaruhi dompet.
* `-alertnotify` akan memanggil perintah untuk menerima peringatan dari jaringan.
* `-par` sekarang mengambil angka negatif, untuk membiarkan sejumlah core bebas.

JSON-RPC API changes
--------------------

* `listunspent` now lists account and address infromation.
* `getinfo` now also returns the time adjustment estimated from your peers.
* `getpeerinfo` now returns bytessent, bytesrecv and syncnode.
* `gettxoutsetinfo` returns statistics about the unspent transaction output database.
* `gettxout` returns information about a specific unspent transaction output.

Perubahan API JSON-RPC
--------------------

* `listunspent` sekarang mencantumkan akun dan alamat infromation.
* `getinfo` sekarang juga mengembalikan penyesuaian waktu yang diperkirakan dari rekan-rekan Anda.
* `getpeerinfo` sekarang kembali bytessent, bytesrecv dan syncnode.
* `gettxoutsetinfo` mengembalikan statistik tentang database hasil transaksi yang tidak terpakai.
* `gettxout` mengembalikan informasi tentang keluaran transaksi tertentu yang tidak terpakai.

Networking changes
------------------

* Significant changes to the networking code, reducing latency and memory consumption.
* Avoid initial block download stalling.
* Remove IRC seeding support.
* Performance tweaks.
* Added testnet DNS seeds.

Jaringan berubah
------------------

* Perubahan signifikan pada kode jaringan, mengurangi latency dan konsumsi memori.
Hindari unduhan unduhan blok awal.
* Hapus dukungan penyemaian IRC.
* Performa tweak.
* Ditambahkan biji testnet DNS.

Wallet compatibility/rescuing
-----------------------------

* Cases where wallets cannot be opened in another version/installation should be reduced.
* `-salvagewallet` now works for encrypted wallets.

Kompatibilitas / penyelamatan dompet
-----------------------------

* Kasus dimana dompet tidak bisa dibuka di versi / instalasi lain harus dikurangi.
* `-salvagewallet` sekarang bekerja untuk dompet terenkripsi.
