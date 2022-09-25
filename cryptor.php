<?php

declare(strict_types=1);

require __DIR__ . "/config.php";
require __DIR__ . "/cli.php";


$argv = $_SERVER["argv"];

$action = "";
$kdf_level = "";
$input_file = "";
$output_file = "";
$input_data = "";
$output_data = "";
$passphrase = "";
$master_key = "";
$key_encryption_key = "";


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

register_shutdown_function(function() use (&$input_file , &$input_data , &$passphrase , &$master_key , &$key_encryption_key) {
	sodium_memzero($input_file);
	sodium_memzero($input_data);
	sodium_memzero($passphrase);
	sodium_memzero($master_key);
	sodium_memzero($key_encryption_key);
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
}

/* parse input file */
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
/* parse output file */
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





/* realpath replacement usable for nonexistent files/dirs */
function _realpath(string $path):string {
	return dirname($path) . "/" . basename($path);
}

function print_help():void {
	global $tty_out;
	fwrite($tty_out , "usage: cryptor [enc] [-<kdf-level>] [dec] <file> [<output-file>]\n");
}


?>