<?php

declare(strict_types=1);


$cli_windows_obscureprompt_status = FALSE;


sapi_windows_set_ctrl_handler(function(int $event) {
	global $cli_windows_obscureprompt_status;
	global $tty_out;
	fwrite($tty_out , "\033[0m");
	cli_clear_screen();
	$cli_windows_obscureprompt_status = FALSE;
});


function cli_linux_disable_echo():bool {
	exec("stty -echo" , $output , $exitcode);
	if ($exitcode !== 0) {
		return FALSE;
	}
	return TRUE;
}

function cli_linux_enable_echo():bool {
	exec("stty echo" , $output , $exitcode);
	if ($exitcode !== 0) {
		return FALSE;
	}
	return TRUE;
}

function cli_clear_screen():void {
	global $tty_out;
	fwrite($tty_out , "\e[H\e[J");
}

function cli_read_line_obscured(string $prompt = "" , string &$password , string &$errormsg):bool {
	global $cli_windows_obscureprompt_status;
	global $tty_in;
	global $tty_out;
	$error = TRUE;
	$line = "";
	$line_trimmed = "";
	fwrite($tty_out , $prompt);
	if (PHP_OS === "Linux") {
		if (!cli_linux_disable_echo()) {
			$errormsg = "failed to read input";
			goto end;
		}
	} else {
		$cli_windows_obscureprompt_status = TRUE;
		fwrite($tty_out , "\033[30;40m");
	}
	$line = fgets($tty_in);
	if ($line == FALSE && $line !== "") {
		$line = "";
		$errormsg = "failed to read input";
		goto end;
	}
	$line_trimmed = trim($line , "\r\n");
	if (PHP_OS === "Linux") {
		if (!cli_linux_enable_echo()) {
			$errormsg = "failed to read input";
			goto end;
		}
	} else {
		fwrite($tty_out , "\033[0m");
		cli_clear_screen();
		$cli_windows_obscureprompt_status = FALSE;
	}
	$password = $line_trimmed;

	$error = FALSE;
	
	end:
		sodium_memzero($line);
		sodium_memzero($line_trimmed);
		fwrite($tty_out , "\033[0m");
		cli_clear_screen();
		$cli_windows_obscureprompt_status = FALSE;

		return !$error;
}

function cli_prompt_password(string $prompt = "" , string &$password , string &$errormsg):bool {
	if (cli_read_line_obscured($prompt , $password , $errormsg) !== TRUE) {
		return FALSE;
	}
	if ($password == "") {
		$errormsg = "password cannot be empty";
		return FALSE;
	}
	return TRUE;
}

function cli_prompt_password_verify(string $prompt = "" , string $verify_prompt = "" , string &$password , string &$errormsg):bool {
	$error = TRUE;
	$password_1 = "";
	$password_2 = "";

	if (cli_prompt_password($prompt , $password_1 , $errormsg) !== TRUE) {
		goto end;
	}
	if (cli_prompt_password($verify_prompt , $password_2 , $errormsg) !== TRUE) {
		goto end;
	}
	/* compare passwords */
	if (hash_equals($password_1 , $password_2) !== TRUE) {
		$errormsg = "passwords don't match";
		goto end;
	}
	$password = $password_1;

	$error = FALSE;

	end:
		sodium_memzero($password_1);
		sodium_memzero($password_2);

		return !$error;
}

?>