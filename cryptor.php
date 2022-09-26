<?php

declare(strict_types=1);

require __DIR__ . "/config.php";
require __DIR__ . "/cli.php";


$argv = $_SERVER["argv"];

$action = "";

$input_file = "";
$input_data = "";

$output_file = "";
$output_data = "";

$passphrase = "";
$master_key = "";
$key_encryption_key = "";

$kdf_salt = "";
$key_encryption_nonce = "";
$data_encryption_nonce = "";

$encrypted_master_key = "";

$kdf_level = NULL;


/* open tty */

if (PHP_OS === "WINNT") {
	$tty_str = "con"; /* Windows console device */
} else {
	$tty_str = "/dev/tty"; /* active POSIX tty */
}
$tty_in = fopen($tty_str , "r");
$tty_out = fopen($tty_str , "w");
if (!$tty_in || !$tty_out) {
	echo "failed to open tty\n";
	exit(1);
}

register_shutdown_function(function() use (&$input_file , &$input_data , &$output_file , &$output_data , &$passphrase , &$master_key , &$key_encryption_key , &$kdf_salt , &$key_encryption_nonce , &$data_encryption_nonce , &$encrypted_master_key) {
	sodium_memzero($input_file);
	sodium_memzero($input_data);
	sodium_memzero($output_file);
	sodium_memzero($output_data);
	sodium_memzero($passphrase);
	sodium_memzero($master_key);
	sodium_memzero($key_encryption_key);
	sodium_memzero($kdf_salt);
	sodium_memzero($key_encryption_nonce);
	sodium_memzero($data_encryption_nonce);
	sodium_memzero($encrypted_master_key);
});


/* parse arguments */

$i = 1;
/* parse action */
if (!isset($argv[$i])) {
	print_help();
	exit(1);
}
if ($argv[$i] === "enc") {
	$action = "encrypt";
} else if ($argv[$i] === "dec") {
	$action = "decrypt";
} else {
	print_help();
	exit(1);
}
$i+= 1;

if (!isset($argv[$i])) {
	print_help();
	exit(1);
}
/* parse kdf level */
if (strlen($argv[$i]) <= 3 && strpos($argv[$i] , "-") !== FALSE && $argv[$i] !== "-") {
	$arg = str_replace("-" , "" , $argv[$i]);
	if (!is_numeric($arg) || strval(intval($arg)) !== $arg || preg_match("/^[0-9]+$/" , $arg) !== 1) {
		print_help();
		exit(1);
	}
	$kdf_level = intval($arg);
	$i+= 1;
} else {
	if ($action === "encrypt") {
		$kdf_level = DEFAULT_KDF_LEVEL;
	}
}

/* parse and validate input file */
if (!isset($argv[$i])) {
	print_help();
	exit(1);
}
if ($argv[$i] === "-") {
	$input_file = "-";
} else {
	$input_file = _realpath(getcwd() . "/" . $argv[$i]);
	if ($input_file == FALSE || !file_exists($input_file)) {
		fwrite($tty_out , "FATAL: input file not found\n");
		exit(1);
	}
	if (!is_file($input_file)) {
		fwrite($tty_out , "FATAL: input file is not a file");
		exit(1);
	}
	if (!is_readable($input_file)) {
		fwrite($tty_out , "FATAL: unable to read input file\n");
		exit(1);
	}
}
$i+= 1;
/* parse and validate output file */
if (!isset($argv[$i])) {
	if ($input_file === "-") {
		fwrite($tty_out , "FATAL: no output specified\n");
		exit(1);
	} else {
		$output_file = $input_file . "." . DEFAULT_ENC_FILE_EXT;
	}
} else {
	if ($argv[$i] === "-") {
		$output_file = "-";
	} else {
		$output_file = _realpath(getcwd() . "/" . $argv[$i]);
		if (file_exists($output_file)) {
			fwrite($tty_out , "FATAL: output file already exists\n");
			exit(1);
		}
	}
}


/* read input file */

if ($input_file === "-") {
	$input_data = file_get_contents("php://stdin");
} else {
	$input_data = file_get_contents($input_file);
}
if ($input_data === FALSE) {
	fwrite($tty_out , "FATAL: failed to read input\n");
	exit(1);
}
if ($action === "decrypt") {
	if (strlen($input_data) < (2 + 16 + 24 + (32 + 16) + 24 + 0 + 16)) { /* kdf_level + salt + key_encryption_nonce + (encrypted_master_key + master_key_tag) + data_encryption_nonce + (encrypted_data + data_tag) */
		fwrite($tty_out , "FATAL: file to decrypt is too short to contain necessary metadata\n");
		exit(1);
	}
}


/* ask passphrase */

if ($action === "encrypt") {
	$errormsg = "";
	$success = cli_prompt_passphrase_verify("passphrase: " , "retype passphrase: " , $passphrase , $errormsg);
	if (!$success) {
		fwrite($tty_out , $errormsg . "\n");
		exit(1);
	}
} else {
	$errormsg = "";
	$success = cli_prompt_passphrase("passphrase: " , $passphrase , $errormsg);
	if (!$success) {
		fwrite($tty_out , $errormsg . "\n");
		exit(1);
	}
}



if ($action === "encrypt") {
	/* generate salt */
	$kdf_salt = random_bytes(16);
} else {
	/* get kdf level */
	$kdf_level_str = substr($input_data , 0 , 2);
	if (!is_numeric($kdf_level_str) || str_pad(strval(intval($kdf_level_str)) , 2 , "0" , STR_PAD_LEFT) !== $kdf_level_str || preg_match("/^[0-9]+$/" , $kdf_level_str) !== 1) {
		fwrite($tty_out , "FATAL: file to decrypt contains invalid kdf level parameter\n");
		exit(1);
	}
	$kdf_level = intval($kdf_level_str);
	/* get salt */
	$kdf_salt = substr($input_data , 2 , 16);
}


/* derive key encryption key */

fwrite($tty_out , "KDF Level = " . $kdf_level . "\n");
$start_time = microtime(TRUE);
$key_encryption_key = sodium_crypto_pwhash(32 , $passphrase , $kdf_salt , get_kdf_ops($kdf_level) , get_kdf_mem($kdf_level) , SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
fwrite($tty_out , "KDF took " . (microtime(TRUE) - $start_time) . "s\n");


if ($action === "encrypt") {
	/* generate master key */
	$master_key = random_bytes(32);
	/* generate nonce */
	$key_encryption_nonce = random_bytes(24);
	/* encrypt master key with key_encryption_key */
	$encrypted_master_key = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($master_key , "" , $key_encryption_nonce , $key_encryption_key);
	if ($encrypted_master_key === FALSE) {
		fwrite($tty_out , "FATAL: failed to encrypt master key\n");
		exit(1);
	}
} else {
	/* read key encryption nonce */
	$key_encryption_nonce = substr($input_data , 18 , 24);
	/* read encrypted master key */
	$encrypted_master_key = substr($input_data , 42 , 48); /* encrypted key + auth tag */
	/* decrypt master key with key_encryption_key */
	$master_key = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($encrypted_master_key , "" , $key_encryption_nonce , $key_encryption_key);
	if ($master_key == FALSE) {
		fwrite($tty_out , "invalid passphrase\n");
		exit(1);
	}
}


if ($action === "encrypt") {
	/* generate data encryption nonce */
	$data_encryption_nonce = random_bytes(24);
	/* encrypt data */
	$encrypted_data = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($input_data , "" , $data_encryption_nonce , $master_key);
	if ($encrypted_data == FALSE) {
		fwrite("FATAL: failed to encrypt data\n");
		exit(1);
	}
	$output_data = str_pad(strval($kdf_level) , 2 , "0" , STR_PAD_LEFT) . $kdf_salt . $key_encryption_nonce . $encrypted_master_key . $data_encryption_nonce . $encrypted_data;
} else {
	/* read data encryption nonce */
	$data_encryption_nonce = substr($input_data , 90 , 24);
	/* decrypt data */
	$output_data = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($input_data , 114) , "" , $data_encryption_nonce , $master_key);
	if ($output_data == FALSE) {
		fwrite("FATAL: failed to decrypt data");
		exit(1);
	}
}


/* write output data */

if ($output_file === "-") {
	$success = file_put_contents("php://stdout" , $output_data);
} else {
	$success = file_put_contents($output_file , $output_data);
}
if (!$success) {
	fwrite($tty_out , "FATAL: failed to write output data\n");
}





function get_kdf_ops(int $kdf_level):int {
	return (int) round($kdf_level / 2);
}

function get_kdf_mem(int $kdf_level):int {
	return (int) round($kdf_level / 8 * (1 << 30));
}

/* realpath replacement usable for nonexistent files/dirs */
function _realpath(string $path):string {
	return dirname($path) . "/" . basename($path);
}

function print_help():void {
	global $tty_out;
	fwrite($tty_out , "usage: cryptor [enc] [-<kdf-level>] [dec] <file> [<output-file>]\n");
}


?>