<?php
require_once __DIR__ . '/../vendor/autoload.php';

class TrieNode {
    public $next;
    public $failure;
    public $outputs;

    public function __construct() {
        $this->next = [];
        $this->failure = null;
        $this->outputs = [];
    }
}

class Detector {
    
    
    function isEncoded($input) {
        if (preg_match('/%[0-9A-Fa-f]{2}/', $input)) {
    
        // Algorithm: Detect URL encoding
            $decodedInput = urldecode($input);
            if ($decodedInput !== false) {
                return [true, $decodedInput];
            }
        }
    
        // Algorithm: Detect Base64 encoding
        $decodedInput = base64_decode($input, true);
        if ($decodedInput !== false) {
            return [true, $decodedInput];
        }
    
        // Algorithm: Detect Hexadecimal encoding
        $decodedInput = hex2bin($input);
        if ($decodedInput !== false) {
            return [true, $decodedInput];
        }
    
        // Algorithm: Detect other custom encoding techniques
        // Add your custom encoding detection logic here
    
        return [false, $input];
        }
    
    
    // Function to detect potential SQL injection using regex
    function detectSqlInjection($params) {
        // Read the text file into an array
        $lines = file(__DIR__ . '/patterns/regexpatterns.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        // Initialize the $injectionPatterns array
        $injectionPatterns = array();

        // Iterate over the lines
        foreach ($lines as $line) {
            // Add each line as a new element in $injectionPatterns array
            $injectionPatterns[] = $line;
        }

        $injectedParams = [];

        foreach ($params as $name => $value) {
            
            list($encoded, $decodedInput) = $this->isEncoded($value);

            if ($encoded) {
                
            $currentDate = date('Y-m-d');
            $currentDateTime = date('Y-m-d_H-i-s');
            $responseLog = "Detector Response:" . PHP_EOL;
            $responseLog .= "Status Code: 200" . PHP_EOL;
            $responseLog .= "Detected at:'$currentDateTime' " . PHP_EOL;
            $responseLog .= "Content-Type: text/plain" . PHP_EOL;
            $responseLog .= "Body: Encoded, Nilai input dari '$value' diencode: " . $decodedInput . PHP_EOL;
            file_put_contents(__DIR__ . "/logs/log-Detector-{$currentDate}.txt", $responseLog, FILE_APPEND);
            
            } else {
                   
            $currentDate = date('Y-m-d');
            $currentDateTime = date('Y-m-d_H-i-s');
            $responseLog = "Detector Response:" . PHP_EOL;
            $responseLog .= "Status Code: 200" . PHP_EOL;
            $responseLog .= "Detected at:'$currentDateTime' " . PHP_EOL;
            $responseLog .= "Content-Type: text/plain" . PHP_EOL;
            $responseLog .= "Body: Decoded, Nilai input dari '$value' tetap: " . $decodedInput . PHP_EOL;
            file_put_contents(__DIR__ . "/logs/log-Detector-{$currentDate}.txt", $responseLog, FILE_APPEND);
            
            }

            foreach ($injectionPatterns as $pattern) {
                if (preg_match($pattern, $decodedInput)) {
                    // SQL injection pattern detected
                    $injectedParams[$name] = $decodedInput;
                    break;
                } else {
                    // Handle other cases here
                }
            }
        }

        return $injectedParams;
    }

    // Function to construct the Trie and Failure function
    function constructTrie($patterns) {
        $root = new TrieNode();

        foreach ($patterns as $pattern) {
            $node = $root;

            for ($i = 0; $i < strlen($pattern); $i++) {
                $char = $pattern[$i];

                if (!isset($node->next[$char])) {
                    $node->next[$char] = new TrieNode();
                }

                $node = $node->next[$char];
            }

            $node->outputs[] = $pattern;
        }

        // Construct Failure function using BFS (Breadth-First Search)
        $queue = new \SplQueue();

        foreach ($root->next as $child) {
            $child->failure = $root;
            $queue->enqueue($child);
        }

        while (!$queue->isEmpty()) {
            $node = $queue->dequeue();

            foreach ($node->next as $char => $child) {
                $queue->enqueue($child);

                $failure = $node->failure;

                while (!isset($failure->next[$char]) && $failure !== $root) {
                    $failure = $failure->failure;
                }

                if (isset($failure->next[$char])) {
                    $child->failure = $failure->next[$char];

                    foreach ($child->failure->outputs as $output) {
                        $child->outputs[] = $output;
                    }
                } else {
                    $child->failure = $root;
                }
            }
        }

        return $root;
    }

    // Function to perform Aho-Corasick pattern matching
    function ahoCorasick($input, $patterns) {
        $root = $this->constructTrie($patterns);
        $output = [];

        $node = $root;

        for ($i = 0; $i < strlen($input); $i++) {
            $char = $input[$i];

            while (!isset($node->next[$char]) && $node !== $root) {
                $node = $node->failure;
            }

            if (isset($node->next[$char])) {
                $node = $node->next[$char];

                if (!empty($node->outputs)) {
                    $output = array_merge($output, $node->outputs);
                }
            }
        }

        return $output;
    }

    // Function to perform SQL injection detection using Aho-Corasick
    function detectSQLInjection2($inputs) {
        $patterns = file(__DIR__ . '/patterns/ahocorasickpatterns.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        $injectedParams = [];

        foreach ($inputs as $name => $value) {

            list($encoded, $decodedInput) = $this->isEncoded($value);

            if ($encoded) {
                
            $currentDate = date('Y-m-d');
            $currentDateTime = date('Y-m-d_H-i-s');
            $responseLog = "Detector Response:" . PHP_EOL;
            $responseLog .= "Status Code: 200" . PHP_EOL;
            $responseLog .= "Detected at:'$currentDateTime' " . PHP_EOL;
            $responseLog .= "Content-Type: text/plain" . PHP_EOL;
            $responseLog .= "Body: Encoded, Nilai input dari '$value' diencode: " . $decodedInput . PHP_EOL;
            file_put_contents(__DIR__ . "/logs/log-Detector-{$currentDate}.txt", $responseLog, FILE_APPEND);
            
            } else {
                   
            $currentDate = date('Y-m-d');
            $currentDateTime = date('Y-m-d_H-i-s');
            $responseLog = "Detector Response:" . PHP_EOL;
            $responseLog .= "Status Code: 200" . PHP_EOL;
            $responseLog .= "Detected at:'$currentDateTime' " . PHP_EOL;
            $responseLog .= "Content-Type: text/plain" . PHP_EOL;
            $responseLog .= "Body: Decoded, Nilai input dari '$value' tetap: " . $decodedInput . PHP_EOL;
            file_put_contents(__DIR__ . "/logs/log-Detector-{$currentDate}.txt", $responseLog, FILE_APPEND);
            
            }

            $matches = $this->ahoCorasick($decodedInput, $patterns);

            if (!empty($matches)) {
                // SQL injection pattern detected
                $injectedParams[$name] = $decodedInput;
            }
        }

        return $injectedParams;
    }

    // Function to perform the injection detection
    function performInjectionDetection($input) {
  



        $sqlInjectionParams = $this->detectSqlInjection($input);

        if (!empty($sqlInjectionParams)) {
            // Potential SQL injection detected
            // Take necessary actions, such as logging or blocking the request
            $queryParams = http_build_query($sqlInjectionParams);
            header("Location: /../vendor/satuduasatu/sqlid/src/result/injection_result.php?$queryParams");

            // Menampilkan HTTP response
            $currentDateTime = date('Y-m-d_H-i-s');
            $responseLog = "HTTP Response:" . PHP_EOL;
            $responseLog .= "Status Code: 400" . PHP_EOL;
            $responseLog .= "Headers: " . PHP_EOL;
            $responseLog .= "Content-Type: text/plain" . PHP_EOL;
            $responseLog .= "Body: Bad Request, SQL Injection Detected by Regex: " . $queryParams . '.' . PHP_EOL;
            file_put_contents(__DIR__ . "/logs/log-Response-{$currentDateTime}.txt", $responseLog, FILE_APPEND);
            
            exit;
        } else {
            $sqlInjectionParams2 = $this->detectSQLInjection2($input);

            if (!empty($sqlInjectionParams2)) {
                // Potential SQL injection detected
                // Take necessary actions, such as logging or blocking the request
                $queryParams = http_build_query($sqlInjectionParams2);
                header("Location: /../vendor/satuduasatu/sqlid/src/result/injection_result.php?$queryParams");

                // Menampilkan HTTP response
                $currentDateTime = date('Y-m-d_H-i-s');
                $responseLog = "HTTP Response:" . PHP_EOL;
                $responseLog .= "Status Code: 400" . PHP_EOL;
                $responseLog .= "Headers: " . PHP_EOL;
                $responseLog .= "Content-Type: text/plain" . PHP_EOL;
                $responseLog .= "Body: Bad Request, SQL Injection Detected by Aho-Corasick: " . $queryParams . '.' . PHP_EOL;
                file_put_contents(__DIR__ . "/logs/log-Response-{$currentDateTime}.txt", $responseLog, FILE_APPEND);
                
                exit;
            } else if (empty($sqlInjectionParams) && empty($sqlInjectionParams2)) {
                $currentDateTime = date('Y-m-d_H-i-s');
                $responseLog = "HTTP Response:" . PHP_EOL;
                $responseLog .= "Status Code: 200" . PHP_EOL;
                $responseLog .= "Headers: " . PHP_EOL;
                $responseLog .= "Content-Type: text/plain" . PHP_EOL;
                $responseLog .= "Body: Save " . PHP_EOL;
                file_put_contents(__DIR__ . "/logs/log-Response-{$currentDateTime}.txt", $responseLog, FILE_APPEND);
                
            } else {
                $currentDateTime = date('Y-m-d_H-i-s');
                $responseLog = "HTTP Response:" . PHP_EOL;
                $responseLog .= "Status Code: 500" . PHP_EOL;
                $responseLog .= "Headers: " . PHP_EOL;
                $responseLog .= "Content-Type: text/plain" . PHP_EOL;
                $responseLog .= "Body: Internal Server Error" . PHP_EOL;
                file_put_contents(__DIR__ . "/logs/log-Response-{$currentDateTime}.txt", $responseLog, FILE_APPEND);
                
    
            }
        }
    }

    // Function to perform the injection detection on all inputs
    function detectAllInjections() {

        $currentDateTime = date('Y-m-d_H-i-s');
        // Menampilkan HTTP request
        $requestLog = "HTTP Request:" . PHP_EOL;
        $requestLog .= "Method: " . $_SERVER['REQUEST_METHOD'] . PHP_EOL;
        $requestLog .= "Headers: " . PHP_EOL;
        $requestLog .= print_r(getallheaders(), true) . PHP_EOL;
        $requestLog .= "Body: " . file_get_contents('php://input') . PHP_EOL;
        file_put_contents(__DIR__ . "/logs/log-Request-{$currentDateTime}.txt", $requestLog, FILE_APPEND);
    
        $input = array_merge($_POST, $_GET);
        $this->performInjectionDetection($input);
    }
}

$detector = new Detector();
$detector->detectAllInjections();

?>
