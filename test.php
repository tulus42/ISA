<?php


$GLOBALS['directory_path'] = "tests/";





// RETURN VALUE
function check_return_val($ret_val, $file_name) {
    $file_name = str_replace(".src", ".rc", $file_name);

    if (file_exists($file_name)) {
        $fh = fopen($file_name, 'r');
    } else {
        $fh = fopen($file_name, 'w+');
        fwrite($fh, 0);
        fclose($fh);

        $fh = fopen($file_name, 'r');
    }

    $file_ret = fread($fh, filesize($file_name));

    fclose($fh);

    if ($file_ret == $ret_val) {
        return TRUE;
    } else {
        return FALSE;
    }
}



// OUTPUT PARSE
function check_output_parse($program_output, $file_name) {
    $file_name = str_replace(".src", ".out", $file_name);

    if (file_exists($file_name)) {
        $fh = fopen($file_name, 'r');
    } else {
        $fh = fopen($file_name, 'w+');
        fclose($fh);

        $fh = fopen($file_name, 'r');
    }

    $output_file = fopen($program_output, 'r');
    $output = fread($output_file, filesize($program_output));

    if (filesize($file_name) != 0) {
        $file_out = fread($fh, filesize($file_name));

        echo("Ocakavany: ".$file_out."\r\n");
        echo("Vrateny:   ".$output."\r\n");

        if (strpos($output, $file_out) != FALSE) {
            fclose($output_file);
            fclose($fh);
            return TRUE;
        } else {
            fclose($output_file);
            fclose($fh);
            return FALSE;
        }
    }
    

    fclose($output_file);
    fclose($fh);
}


///////////////////////////////////////////////////////
// PARSE TESTS
///////////////////////////////////////////////////////
function run_tests($exec_file) {
    $dir_path = $GLOBALS['directory_path']; 

    $GLOBALS['html_code'] .=  "        <h2 style=\"color: indigo\">DNS tests:</h2>";

    echo($dir_path."\r\n");

    foreach (glob($dir_path."*.src") as $source_file) {
        $output = "";

        $input_args_file = fopen($source_file, 'r');

        $input_args = fgets($input_args_file);

        exec("./dns ".$input_args." 2>&1", $output, $return_var);

        
        // create tmp file for exec output
        $fh = fopen("tmp.txt", 'w+');

        file_put_contents('tmp.txt', $output);

        fclose($fh);

        $ret_val = check_return_val($return_var, $source_file);
        // $out_val = check_output_parse("tmp.txt", $source_file);
        
        // html_element($ret_val, $out_val, $source_file, $return_var);

        html_element($ret_val, TRUE, $source_file, $return_var);
        fclose($input_args_file);
    }
}






///////////////////////////////////////////////////////
// HTML
///////////////////////////////////////////////////////
function html_header() {
    return "<!DOCTYPE html>
    <html lang=\"en\">
        <head>
            <meta charset=\"UTF-8\">
            <title>Testing log</title>
        </head>
        <body>
            <h1 style=\"text-align: center; color: darkred\">Testing log</h1>";
}


function html_element($ret_val, $out_val, $source_file, $return_var) {
    if ($ret_val && ($return_var != 0)) {
        $GLOBALS['html_code'] .= "<h3 style=\"color:limegreen\">".$source_file."</h3>
        <p style=\"margin-left: 60px; color:limegreen\">Returned value: CORRECT - non 0</p>";

        $GLOBALS['correct_test_counter'] += 1;

    } elseif ($ret_val) {
        if ($out_val) {
            $GLOBALS['html_code'] .= "<h3 style=\"color:limegreen\">".$source_file."</h3>
            <p style=\"margin-left: 60px; color:limegreen\">Returned value: CORRECT</p>";

            $GLOBALS['correct_test_counter'] += 1;
            
        } else {
            $GLOBALS['html_code'] .= "<h3 style=\"color:red\">".$source_file."</h3>
            <p style=\"margin-left: 60px; color:limegreen\">Returned value: CORRECT</p>";
        }

    } else {
        $GLOBALS['html_code'] .= "<h3 style=\"color:red\">".$source_file."</h3>
        <p style=\"margin-left: 60px; color:red\">Returned value: FAIL - returned: ".$return_var."</p>";
    }

    $GLOBALS['test_counter'] += 1;
}


function end_html($string) {
    $res = ($GLOBALS['correct_test_counter'] / $GLOBALS['test_counter']) * 100;
    $string .= "        <h2 style=\"color: indigo\">Results: ".round($res,2)."%</h2>
    <p style=\"margin-left: 60px\">Succesfull tests: ".$GLOBALS['correct_test_counter']."</p>
    <p style=\"margin-left: 60px\">All tests: ".$GLOBALS['test_counter']."</p>
    \n    </body>
    </html>";

    file_put_contents("DNS_TEST_LOG.html", $string);
}

///////////////////////////////////////////////////////
// MAIN
///////////////////////////////////////////////////////
$exec_file = "dns";

$directory_path = "tests/";

$test_counter = 0;
$correct_test_counter = 0;


$html_code = html_header();

run_tests($exec_file);


end_html($html_code);

?>
