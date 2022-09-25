<?php

declare(strict_types=1);

const DEFAULT_ENC_FILE_EXT = "enc";


$argv = $_SERVER["argv"];

$action = NULL;
$kdf_level = NULL;
$input_file = NULL;
$output_file = NULL;

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
		echo $input_file . "\n";
		echo "FATAL: input file not found\n";
		exit(1);
	}
	if (!is_file($input_file)) {
		echo "FATAL: input file is not a file";
		exit(1);
	}
	if (!is_readable($input_file)) {
		echo "FATAL: unable to read input file\n";
		exit(1);
	}
}
$i+= 1;
/* parse output file */
if (!isset($argv[$i])) {
	if ($input_file === "-") {
		echo "FATAL: no output specified\n";
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
			echo "FATAL: output file already exists\n";
			exit(1);
		}
	}
}


echo "action:\t" . $action . "\n";
echo "kdf_level:\t" . $kdf_level . "\n";
echo "input:\t" . $input_file . "\n";
echo "output:\t" . $output_file . "\n";





/* realpath replacement usabe for nonexistent files/dirs */
function _realpath(string $path):string {
	return dirname($path) . "/" . basename($path);
}

function print_help():void {
	echo "usage: cryptor [enc] [-<kdf-level>] [dec] <file> [<output-file>]\n";
}


?>