#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <regex.h>
#include <stdbool.h>
#include <jansson.h>

#define MAX_PATH_LENGTH 1024
#define MAX_LINE_LENGTH 4096
#define MAX_PATTERN_LENGTH 256
#define MAX_PATTERNS 50
#define MAX_DESCRIPTION_LENGTH 512
#define MAX_CODE_SNIPPET_LENGTH 1024
#define MAX_RESULTS 500

typedef struct {
    char pattern[MAX_PATTERN_LENGTH];
    char description[MAX_DESCRIPTION_LENGTH];
    float severity;
} VulnerabilityPattern;

typedef struct {
    char code[MAX_CODE_SNIPPET_LENGTH];
    int line;
    char file[MAX_PATH_LENGTH];
    char description[MAX_DESCRIPTION_LENGTH];
} VulnerabilityOccurrence;

typedef struct {
    char type[50];
    VulnerabilityOccurrence occurrences[MAX_RESULTS];
    int count;
} VulnerabilityResult;

typedef struct {
    VulnerabilityResult results[MAX_PATTERNS];
    int count;
    char filepath[MAX_PATH_LENGTH];
    float risk_score;
    char risk_level[20];
} FileAnalysisResult;

// Memory management vulnerability patterns
VulnerabilityPattern memory_patterns[] = {
    {"\\bmalloc\\([^)]*\\)\\s*;", "Malloc without checking return value", 8.0},
    {"\\bcalloc\\([^)]*\\)\\s*;", "Calloc without checking return value", 8.0},
    {"\\brealloc\\([^)]*\\)\\s*;", "Realloc without checking return value", 8.0},
    {"\\bfree\\(\\s*[^)]*\\)\\s*;\\s*.*\\bfree\\(\\s*\\1\\s*\\)", "Double free vulnerability", 9.5},
    {"\\bfree\\(\\s*NULL\\s*\\)", "Free of NULL pointer (potential logic error)", 5.0},
    {"\\bfree\\(([^)]*)\\);\\s+.*\\1", "Use after free vulnerability", 9.0},
    {"\\bmemcpy\\([^,]*, [^,]*, sizeof\\([^*)]", "Memcpy with potentially incorrect size", 7.5},
    {"\\bmemcpy\\([^,]*, [^,]*, [^,]*(?<!sizeof\\s*\\([^)]*\\))\\s*\\)", "Memcpy with hardcoded size", 6.5},
    {"\\bstrncpy\\([^,]*, [^,]*, sizeof\\([^)]\\)", "Strncpy without null-termination check", 7.0},
    {"\\bstrcpy\\(", "Use of strcpy instead of strncpy", 8.0},
    {"\\bstrcat\\(", "Use of strcat instead of strncat", 8.0},
    {"\\bgets\\(", "Use of gets (always unsafe)", 10.0},
    {"\\bscanf\\(", "Use of scanf without field width limits", 7.5},
    {"\\bsprintf\\(", "Use of sprintf instead of snprintf", 8.0}
};

// Integer overflow/underflow patterns
VulnerabilityPattern integer_patterns[] = {
    {"\\bunsigned\\s+(?:int|long|short)\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*[^;]*\\s*-\\s*[0-9]+", "Potential integer underflow with unsigned", 7.0},
    {"\\bint\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*[0-9]+\\s*\\+\\s*[0-9]+", "Potential integer overflow", 6.5},
    {"\\bsize_t\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*[0-9]+\\s*\\+\\s*[0-9]+", "Potential size_t overflow", 6.5},
    {"\\b(int|long|short)\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*[^;]*\\s*<<\\s*[0-9]+", "Potential shift overflow", 7.0},
    {"for\\s*\\([^;]*;[^;]*;[^)]*\\+\\+[^)]*\\)", "Potential loop overflow", 5.0}
};

// Format string vulnerability patterns
VulnerabilityPattern format_string_patterns[] = {
    {"\\bprintf\\s*\\([^,\"]*\\)", "Format string vulnerability in printf", 9.0},
    {"\\bfprintf\\s*\\([^,]*,[^,\"]*\\)", "Format string vulnerability in fprintf", 9.0},
    {"\\bsprintf\\s*\\([^,]*,[^,\"]*\\)", "Format string vulnerability in sprintf", 9.0},
    {"\\bsnprintf\\s*\\([^,]*,[^,]*,[^,\"]*\\)", "Format string vulnerability in snprintf", 9.0},
    {"\\bvsprintf\\s*\\([^,]*,[^,\"]*", "Format string vulnerability in vsprintf", 9.0},
    {"\\bvsnprintf\\s*\\([^,]*,[^,]*,[^,\"]*", "Format string vulnerability in vsnprintf", 9.0}
};

// Command injection patterns
VulnerabilityPattern command_injection_patterns[] = {
    {"\\bsystem\\s*\\([^)]*argv", "Potential command injection using argv", 9.5},
    {"\\bsystem\\s*\\([^)]*getenv", "Potential command injection using getenv", 9.5},
    {"\\bsystem\\s*\\(.*\\+.*\\)", "Potential command injection with concatenation", 9.0},
    {"\\bsystem\\s*\\(\".*\\$.*\"\\)", "Potential command injection with shell variables", 9.0},
    {"\\bpopen\\s*\\([^)]*argv", "Potential command injection using popen with argv", 9.5},
    {"\\bpopen\\s*\\([^)]*getenv", "Potential command injection using popen with getenv", 9.5},
    {"\\bexecl\\s*\\([^)]*argv", "Potential command injection using execl with argv", 9.0},
    {"\\bexeclp\\s*\\([^)]*argv", "Potential command injection using execlp with argv", 9.0},
    {"\\bexecle\\s*\\([^)]*argv", "Potential command injection using execle with argv", 9.0},
    {"\\bexecv\\s*\\([^)]*argv", "Potential command injection using execv with argv", 9.0},
    {"\\bexecvp\\s*\\([^)]*argv", "Potential command injection using execvp with argv", 9.0},
    {"\\bexecve\\s*\\([^)]*argv", "Potential command injection using execve with argv", 9.0}
};

// Path traversal and file inclusion patterns
VulnerabilityPattern path_traversal_patterns[] = {
    {"\\b(fopen|open)\\s*\\([^)]*argv", "Potential path traversal using argv", 8.5},
    {"\\b(fopen|open)\\s*\\([^)]*getenv", "Potential path traversal using getenv", 8.5},
    {"\\b(fopen|open)\\s*\\(.*\\+.*\\)", "Potential path traversal with concatenation", 8.0},
    {"\\b(fopen|open)\\s*\\(\".*%s.*\"", "Potential path traversal with format string", 8.0},
    {"\\baccess\\s*\\([^)]*argv", "Potential path traversal using access with argv", 7.5},
    {"\\bchdir\\s*\\([^)]*argv", "Potential path traversal using chdir with argv", 7.5},
    {"\\bstat\\s*\\([^)]*argv", "Potential path traversal using stat with argv", 7.0},
    {"\\blstat\\s*\\([^)]*argv", "Potential path traversal using lstat with argv", 7.0},
    {"\\bopendir\\s*\\([^)]*argv", "Potential path traversal using opendir with argv", 7.0}
};

// Hardcoded credentials patterns
VulnerabilityPattern hardcoded_credential_patterns[] = {
    {"\\bchar\\s+[a-zA-Z_][a-zA-Z0-9_]*\\[]\\s*=\\s*\"[^\"]*pass", "Hardcoded password", 9.0},
    {"\\bchar\\s+[a-zA-Z_][a-zA-Z0-9_]*\\[]\\s*=\\s*\"[^\"]*secret", "Hardcoded secret", 9.0},
    {"\\bchar\\s+[a-zA-Z_][a-zA-Z0-9_]*\\[]\\s*=\\s*\"[^\"]*admin", "Hardcoded admin credential", 8.5},
    {"\\bchar\\s+[a-zA-Z_][a-zA-Z0-9_]*\\[]\\s*=\\s*\"[^\"]*key", "Hardcoded key", 8.5},
    {"\\bchar\\s+[a-zA-Z_][a-zA-Z0-9_]*\\[]\\s*=\\s*\"[^\"]*token", "Hardcoded token", 8.5},
    {"#define\\s+[A-Z_][A-Z0-9_]*\\s+\"[^\"]*pass", "Hardcoded password in #define", 9.0},
    {"#define\\s+[A-Z_][A-Z0-9_]*\\s+\"[^\"]*secret", "Hardcoded secret in #define", 9.0},
    {"#define\\s+[A-Z_][A-Z0-9_]*\\s+\"[^\"]*admin", "Hardcoded admin credential in #define", 8.5},
    {"#define\\s+[A-Z_][A-Z0-9_]*\\s+\"[^\"]*key", "Hardcoded key in #define", 8.5},
    {"#define\\s+[A-Z_][A-Z0-9_]*\\s+\"[^\"]*token", "Hardcoded token in #define", 8.5}
};

// Backdoor patterns
VulnerabilityPattern backdoor_patterns[] = {
    {"\\bsocket\\s*\\([^)]*\\).*connect\\s*\\([^)]*\\)", "Potential backdoor with socket connection", 9.0},
    {"\\bpthread_create\\s*\\([^)]*\\)", "Hidden functionality in thread", 6.5},
    {"\\bat_exit\\s*\\([^)]*\\)", "Potential backdoor in exit handler", 7.0},
    {"\\bsignal\\s*\\([^)]*\\)", "Potential backdoor in signal handler", 7.0},
    {"\\bfork\\s*\\(\\s*\\).*execl", "Potential backdoor creating new process", 8.5},
    {"#ifdef\\s+.*DEBUG.*\\bsystem\\s*\\(", "Potential hidden command execution in debug code", 7.5},
    {"\\bBOOT_TIME", "Potential time-based backdoor trigger", 8.0},
    {"\\bgetenv\\s*\\(\"[^\"]*\"\\).*\\bsystem\\s*\\(", "Potential environment-triggered backdoor", 9.0},
    {"\\bdlopen\\s*\\([^)]*\\)", "Potential backdoor with dynamic library loading", 7.5},
    {"\\bdlsym\\s*\\([^)]*\\)", "Potential backdoor with dynamic function loading", 7.5}
};

// Network vulnerability patterns
VulnerabilityPattern network_patterns[] = {
    {"\\bbind\\s*\\([^)]*INADDR_ANY", "Binding to all network interfaces", 7.0},
    {"\\baccept\\s*\\([^)]*\\)\\s*;", "Accept without address validation", 6.5},
    {"\\brecv\\s*\\([^)]*\\).*exec", "Execution of received data", 9.5},
    {"\\bsend\\s*\\([^)]*getenv", "Sending environment variables over network", 8.0},
    {"\\bsend\\s*\\([^)]*environ", "Sending environment over network", 8.5},
    {"\\bsend\\s*\\([^)]*fopen", "Sending file contents over network", 7.5},
    {"\\brecv\\s*\\([^)]*\\).*fopen", "Network-influenced file operations", 8.0},
    {"\\bsetsockopt\\s*\\([^)]*SO_REUSEADDR", "Socket configured to reuse address", 4.0},
    {"\\bSSL_CTX_set_verify\\s*\\([^)]*SSL_VERIFY_NONE", "SSL verification disabled", 8.5},
    {"\\bFILE\\s+\\*\\s*[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*NULL;[^;]*recv[^;]*fopen", "Potential network-based file access", 8.0}
};

// Obfuscation patterns
VulnerabilityPattern obfuscation_patterns[] = {
    {"\\b0x[0-9a-fA-F]{2}\\s*,\\s*0x[0-9a-fA-F]{2}", "Obfuscated string using hex values", 7.0},
    {"#define\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s+[a-zA-Z_][a-zA-Z0-9_]*", "Function redefinition (could be obfuscation)", 5.0},
    {"void\\s*\\(\\s*\\*\\s*[a-zA-Z_][a-zA-Z0-9_]*\\s*\\)\\s*\\([^)]*\\)\\s*=", "Function pointer assignment (possible obfuscation)", 6.0},
    {"xor|XOR|^|\\^=", "XOR-based obfuscation", 6.5},
    {"#include\\s+\"[^\"]*\\.[0-9][^\"]*\"", "Suspicious include filename", 6.0},
    {"__asm__|asm\\s+volatile", "Inline assembly usage", 7.0},
    {"\\buintptr_t\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*\\(uintptr_t\\)\\s*[a-zA-Z_][a-zA-Z0-9_]*", "Pointer type casting (potential obfuscation)", 6.0},
    {"\\b(void|char|int)\\s*\\(\\s*\\*\\s*\\)\\s*\\(", "Cast to function pointer (potential obfuscation)", 6.5},
    {"\\bdlsym\\s*\\([^)]*\\)", "Dynamic symbol resolution (potential obfuscation)", 7.0},
    {"#pragma\\s+pack", "Non-standard memory layout", 5.0}
};

// Dangerous function patterns
VulnerabilityPattern dangerous_function_patterns[] = {
    {"\\batoiv*\\s*\\([^)]*\\)", "Potentially unsafe string to number conversion", 6.0},
    {"\\bmemset\\s*\\([^,]*,\\s*0\\s*,\\s*0\\s*\\)", "Ineffective memory clearing with zero size", 7.0},
    {"\\bmktemp\\s*\\(", "Use of insecure mktemp function", 8.0},
    {"\\btmpnam\\s*\\(", "Use of insecure tmpnam function", 8.0},
    {"\\brand\\s*\\(\\s*\\)\\s*%", "Weak random number generation", 7.0},
    {"\\bfread\\s*\\([^)]*\\)\\s*;", "Fread without checking return value", 6.0},
    {"\\bfwrite\\s*\\([^)]*\\)\\s*;", "Fwrite without checking return value", 6.0},
    {"\\bgetwd\\s*\\(", "Use of insecure getwd function", 7.5},
    {"\\blongjmp\\s*\\(", "Use of longjmp (can lead to undefined behavior)", 6.5},
    {"\\bsetjmp\\s*\\(", "Use of setjmp (can lead to undefined behavior)", 6.0}
};

// Suspicious code patterns
VulnerabilityPattern suspicious_patterns[] = {
    {"\\bwhile\\s*\\(\\s*1\\s*\\)\\s*{[^}]*exec", "Infinite loop with command execution", 8.5},
    {"\\bwhile\\s*\\(\\s*1\\s*\\)\\s*{[^}]*system", "Infinite loop with system call", 8.5},
    {"\\bwhile\\s*\\(\\s*1\\s*\\)\\s*{[^}]*recv", "Infinite loop with network receive", 7.0},
    {"\\bif\\s*\\(\\s*geteuid\\s*\\(\\s*\\)\\s*==\\s*0\\s*\\)", "Checking for root privileges", 7.0},
    {"\\bif\\s*\\(\\s*getuid\\s*\\(\\s*\\)\\s*==\\s*0\\s*\\)", "Checking for root user", 7.0},
    {"\\bchmod\\s*\\([^,]*,\\s*[0-7]*7[0-7]*\\)", "Setting dangerous file permissions", 8.0},
    {"\\bchown\\s*\\([^,]*,\\s*0\\s*,", "Changing file ownership to root", 8.0},
    {"\\bseteuid\\s*\\(\\s*0\\s*\\)", "Setting effective UID to root", 9.0},
    {"\\bsetuid\\s*\\(\\s*0\\s*\\)", "Setting UID to root", 9.0},
    {"\\bptrace\\s*\\(", "System call tracing/debugging", 7.5}
};

int compile_regex(regex_t *regex, const char *pattern) {
    int status = regcomp(regex, pattern, REG_EXTENDED);
    if (status != 0) {
        char error_message[MAX_LINE_LENGTH];
        regerror(status, regex, error_message, MAX_LINE_LENGTH);
        fprintf(stderr, "Regex error compiling '%s': %s\n", pattern, error_message);
        return 0;
    }
    return 1;
}

int match_pattern(const char *line, const char *pattern, regmatch_t *match) {
    regex_t regex;
    
    if (!compile_regex(&regex, pattern)) {
        return 0;
    }
    
    int status = regexec(&regex, line, 1, match, 0);
    regfree(&regex);
    
    return (status == 0);
}

void extract_code_snippet(char *snippet, const char *line, regmatch_t *match) {
    int start = match->rm_so;
    int end = match->rm_eo;
    int length = end - start;
    
    if (length >= MAX_CODE_SNIPPET_LENGTH) {
        length = MAX_CODE_SNIPPET_LENGTH - 1;
    }
    
    strncpy(snippet, line + start, length);
    snippet[length] = '\0';
}

void check_pattern_category(FileAnalysisResult *result, const char *filepath, const char *line, int line_num, 
                           VulnerabilityPattern *patterns, int pattern_count, const char *category) {
    for (int i = 0; i < pattern_count; i++) {
        regmatch_t match;
        if (match_pattern(line, patterns[i].pattern, &match)) {
            // Find or create category in results
            int category_index = -1;
            for (int j = 0; j < result->count; j++) {
                if (strcmp(result->results[j].type, category) == 0) {
                    category_index = j;
                    break;
                }
            }
            
            if (category_index == -1) {
                if (result->count >= MAX_PATTERNS) {
                    fprintf(stderr, "Too many vulnerability types, limit reached\n");
                    return;
                }
                category_index = result->count;
                strncpy(result->results[category_index].type, category, sizeof(result->results[category_index].type)-1);
                result->results[category_index].count = 0;
                result->count++;
            }
            
            // Add occurrence
            VulnerabilityResult *vuln_result = &result->results[category_index];
            if (vuln_result->count >= MAX_RESULTS) {
                fprintf(stderr, "Too many occurrences for vulnerability type %s, limit reached\n", category);
                return;
            }
            
            VulnerabilityOccurrence *occurrence = &vuln_result->occurrences[vuln_result->count];
            extract_code_snippet(occurrence->code, line, &match);
            occurrence->line = line_num;
            strncpy(occurrence->file, filepath, sizeof(occurrence->file)-1);
            strncpy(occurrence->description, patterns[i].description, sizeof(occurrence->description)-1);
            
            vuln_result->count++;
        }
    }
}

void analyze_file(FileAnalysisResult *result, const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", filepath);
        return;
    }
    
    // Initialize result
    result->count = 0;
    strncpy(result->filepath, filepath, sizeof(result->filepath)-1);
    result->filepath[sizeof(result->filepath)-1] = '\0';
    result->risk_score = 0.0;
    
    char line[MAX_LINE_LENGTH];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        
        // Skip comments
        if (strncmp(line, "//", 2) == 0 || strncmp(line, "/*", 2) == 0 || strncmp(line, " *", 2) == 0) {
            continue;
        }
        
        // Check for vulnerability patterns in each category
        check_pattern_category(result, filepath, line, line_num, memory_patterns, 
                             sizeof(memory_patterns)/sizeof(memory_patterns[0]), "memory_vulnerabilities");
        
        check_pattern_category(result, filepath, line, line_num, integer_patterns, 
                             sizeof(integer_patterns)/sizeof(integer_patterns[0]), "integer_vulnerabilities");
        
        check_pattern_category(result, filepath, line, line_num, format_string_patterns, 
                             sizeof(format_string_patterns)/sizeof(format_string_patterns[0]), "format_string_vulnerabilities");
        
        check_pattern_category(result, filepath, line, line_num, command_injection_patterns, 
                             sizeof(command_injection_patterns)/sizeof(command_injection_patterns[0]), "command_injection");
        
        check_pattern_category(result, filepath, line, line_num, path_traversal_patterns, 
                             sizeof(path_traversal_patterns)/sizeof(path_traversal_patterns[0]), "path_traversal");
        
        check_pattern_category(result, filepath, line, line_num, hardcoded_credential_patterns, 
                             sizeof(hardcoded_credential_patterns)/sizeof(hardcoded_credential_patterns[0]), "hardcoded_credentials");
        
        check_pattern_category(result, filepath, line, line_num, backdoor_patterns, 
                             sizeof(backdoor_patterns)/sizeof(backdoor_patterns[0]), "backdoor");
        
        check_pattern_category(result, filepath, line, line_num, network_patterns, 
                             sizeof(network_patterns)/sizeof(network_patterns[0]), "network_vulnerabilities");
        
        check_pattern_category(result, filepath, line, line_num, obfuscation_patterns, 
                             sizeof(obfuscation_patterns)/sizeof(obfuscation_patterns[0]), "obfuscated_code");
        
        check_pattern_category(result, filepath, line, line_num, dangerous_function_patterns, 
                             sizeof(dangerous_function_patterns)/sizeof(dangerous_function_patterns[0]), "dangerous_functions");
        
        check_pattern_category(result, filepath, line, line_num, suspicious_patterns, 
                             sizeof(suspicious_patterns)/sizeof(suspicious_patterns[0]), "suspicious_code");
    }
    
    fclose(file);
    
    // Calculate risk score
    float total_severity = 0.0;
    int total_occurrences = 0;
    
    for (int i = 0; i < result->count; i++) {
        VulnerabilityResult *vuln_result = &result->results[i];
        for (int j = 0; j < vuln_result->count; j++) {
            float severity = 5.0; // Default severity
            
            // Try to find the pattern to get its severity
            const char *description = vuln_result->occurrences[j].description;
            
            // Match the description with pattern severity
            #define CHECK_PATTERN_CATEGORY(patterns, count) \
                for (int k = 0; k < count; k++) { \
                    if (strcmp(description, patterns[k].description) == 0) { \
                        severity = patterns[k].severity; \
                        break; \
                    } \
                }
            
            CHECK_PATTERN_CATEGORY(memory_patterns, sizeof(memory_patterns)/sizeof(memory_patterns[0]));
            CHECK_PATTERN_CATEGORY(integer_patterns, sizeof(integer_patterns)/sizeof(integer_patterns[0]));
            CHECK_PATTERN_CATEGORY(format_string_patterns, sizeof(format_string_patterns)/sizeof(format_string_patterns[0]));
            CHECK_PATTERN_CATEGORY(command_injection_patterns, sizeof(command_injection_patterns)/sizeof(command_injection_patterns[0]));
            CHECK_PATTERN_CATEGORY(path_traversal_patterns, sizeof(path_traversal_patterns)/sizeof(path_traversal_patterns[0]));
            CHECK_PATTERN_CATEGORY(hardcoded_credential_patterns, sizeof(hardcoded_credential_patterns)/sizeof(hardcoded_credential_patterns[0]));
            CHECK_PATTERN_CATEGORY(backdoor_patterns, sizeof(backdoor_patterns)/sizeof(backdoor_patterns[0]));
            CHECK_PATTERN_CATEGORY(network_patterns, sizeof(network_patterns)/sizeof(network_patterns[0]));
            CHECK_PATTERN_CATEGORY(obfuscation_patterns, sizeof(obfuscation_patterns)/sizeof(obfuscation_patterns[0]));
            CHECK_PATTERN_CATEGORY(dangerous_function_patterns, sizeof(dangerous_function_patterns)/sizeof(dangerous_function_patterns[0]));
            CHECK_PATTERN_CATEGORY(suspicious_patterns, sizeof(suspicious_patterns)/sizeof(suspicious_patterns[0]));
            
            total_severity += severity;
            total_occurrences++;
        }
    }
    
    if (total_occurrences > 0) {
        float avg_severity = total_severity / total_occurrences;
        float count_factor = 1.0 + (total_occurrences / 10.0 > 1.0 ? 1.0 : total_occurrences / 10.0);
        result->risk_score = avg_severity * count_factor;
        
        if (result->risk_score > 10.0) {
            result->risk_score = 10.0;
        }
    }
    
    // Set risk level based on score
    if (result->risk_score == 0.0) {
        strncpy(result->risk_level, "Safe", sizeof(result->risk_level)-1);
    } else if (result->risk_score < 3.0) {
        strncpy(result->risk_level, "Low", sizeof(result->risk_level)-1);
    } else if (result->risk_score < 6.0) {
        strncpy(result->risk_level, "Medium", sizeof(result->risk_level)-1);
    } else if (result->risk_score < 8.0) {
        strncpy(result->risk_level, "High", sizeof(result->risk_level)-1);
    } else {
        strncpy(result->risk_level, "Critical", sizeof(result->risk_level)-1);
    }
}

void generate_json_report(FileAnalysisResult *results, int result_count) {
    json_t *root = json_array();
    
    for (int i = 0; i < result_count; i++) {
        FileAnalysisResult *result = &results[i];
        
        json_t *file_obj = json_object();
        json_object_set_new(file_obj, "filepath", json_string(result->filepath));
        json_object_set_new(file_obj, "risk_score", json_real(result->risk_score));
        json_object_set_new(file_obj, "risk_level", json_string(result->risk_level));
        
        json_t *vulnerabilities = json_object();
        
        for (int j = 0; j < result->count; j++) {
            VulnerabilityResult *vuln_result = &result->results[j];
            
            json_t *occurrences = json_array();
            
            for (int k = 0; k < vuln_result->count; k++) {
                VulnerabilityOccurrence *occurrence = &vuln_result->occurrences[k];
                
                json_t *occurrence_obj = json_object();
                json_object_set_new(occurrence_obj, "line", json_integer(occurrence->line));
                json_object_set_new(occurrence_obj, "code", json_string(occurrence->code));
                json_object_set_new(occurrence_obj, "file", json_string(occurrence->file));
                json_object_set_new(occurrence_obj, "description", json_string(occurrence->description));
                
                json_array_append_new(occurrences, occurrence_obj);
            }
            
            json_object_set_new(vulnerabilities, vuln_result->type, occurrences);
        }
        
        json_object_set_new(file_obj, "vulnerabilities", vulnerabilities);
        json_array_append_new(root, file_obj);
    }
    
    char *json_result = json_dumps(root, JSON_INDENT(2));
    printf("%s\n", json_result);
    
    free(json_result);
    json_decref(root);
}

void generate_text_report(FileAnalysisResult *results, int result_count) {
    for (int i = 0; i < 80; i++) printf("=");
    printf("\nVULNERABILITY ANALYSIS REPORT\n");
    for (int i = 0; i < 80; i++) printf("=");

    
    for (int i = 0; i < result_count; i++) {
        FileAnalysisResult *result = &results[i];
        
        printf("\n\nFile: %s\n", result->filepath);
        printf("Risk Score: %.1f/10 (%s Risk)\n", result->risk_score, result->risk_level);
        for (int i = 0; i < 80; i++) printf("-");
        
        if (result->count == 0) {
            printf("\nNo vulnerabilities detected.\n");
            continue;
        }
        
        for (int j = 0; j < result->count; j++) {
            VulnerabilityResult *vuln_result = &result->results[j];
            
            // Convert type to a more readable format
            char readable_type[100];
            strncpy(readable_type, vuln_result->type, sizeof(readable_type)-1);
            readable_type[sizeof(readable_type)-1] = '\0';
            
            // Replace underscores with spaces and capitalize words
            for (int k = 0; readable_type[k]; k++) {
                if (readable_type[k] == '_') {
                    readable_type[k] = ' ';
                } else if (k == 0 || readable_type[k-1] == ' ') {
                    readable_type[k] = toupper(readable_type[k]);
                }
            }
            
            printf("\n\n[!] %s (%d occurrences)\n", readable_type, vuln_result->count);
            
            int display_count = vuln_result->count > 5 ? 5 : vuln_result->count;
            
            for (int k = 0; k < display_count; k++) {
                VulnerabilityOccurrence *occurrence = &vuln_result->occurrences[k];
                printf("  %d. Line %d: %s\n", k + 1, occurrence->line, occurrence->code);
                printf("     Description: %s\n", occurrence->description);
            }
            
            if (vuln_result->count > 5) {
                printf("  ... and %d more occurrences\n", vuln_result->count - 5);
            }
        }
    }
}

int scan_directory(const char *directory, char file_list[][MAX_PATH_LENGTH], int max_files) {
    DIR *dir;
    struct dirent *entry;
    int count = 0;
    
    if (!(dir = opendir(directory))) {
        return 0;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            // Skip . and ..
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            
            char path[MAX_PATH_LENGTH];
            snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
            
            // Recursively scan subdirectories
            count += scan_directory(path, &file_list[count], max_files - count);
            
        } else {
            // Check if it's a C/C++ file
            const char *name = entry->d_name;
            const char *ext = strrchr(name, '.');
            
            if (ext && (strcmp(ext, ".c") == 0 || strcmp(ext, ".h") == 0 || strcmp(ext, ".cpp") == 0 || 
                      strcmp(ext, ".cc") == 0 || strcmp(ext, ".hpp") == 0)) {
                char full_path[MAX_PATH_LENGTH];
                snprintf(full_path, sizeof(full_path), "%s/%s", directory, name);
                
                if (count < max_files) {
                    strncpy(file_list[count], full_path, MAX_PATH_LENGTH-1);
                    file_list[count][MAX_PATH_LENGTH-1] = '\0';
                    count++;
                } else {
                    fprintf(stderr, "Warning: Maximum file limit reached\n");
                    break;
                }
            }
        }
    }
    
    closedir(dir);
    return count;
}

void print_usage() {
    printf("Usage: analyzer [OPTIONS] TARGET\n");
    printf("Analyze C/C++ files for security vulnerabilities\n\n");
    printf("Options:\n");
    printf("  --format FORMAT    Output format (text, json), default: text\n");
    printf("  --output FILE      Output file, default: stdout\n");
    printf("  --help             Display this help message\n\n");
    printf("TARGET can be a single file or a directory to scan recursively\n");
}

int main(int argc, char *argv[]) {
    char *target = NULL;
    char *format = "text";
    char *output_file = NULL;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(argv[i], "--format") == 0) {
            if (i + 1 < argc) {
                format = argv[++i];
            } else {
                fprintf(stderr, "Error: --format requires an argument\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                output_file = argv[++i];
            } else {
                fprintf(stderr, "Error: --output requires an argument\n");
                return 1;
            }
        } else if (target == NULL) {
            target = argv[i];
        } else {
            fprintf(stderr, "Error: Unexpected argument '%s'\n", argv[i]);
            print_usage();
            return 1;
        }
    }
    
    if (target == NULL) {
        fprintf(stderr, "Error: No target specified\n");
        print_usage();
        return 1;
    }
    
    // If output file is specified, redirect stdout
    if (output_file != NULL) {
        if (freopen(output_file, "w", stdout) == NULL) {
            fprintf(stderr, "Error: Unable to open output file '%s'\n", output_file);
            return 1;
        }
    }
    
    // Check if target is a file or directory
    struct stat path_stat;
    stat(target, &path_stat);
    
    // Allocate results array
    FileAnalysisResult *results = malloc(MAX_RESULTS * sizeof(FileAnalysisResult));
    if (!results) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }
    
    int result_count = 0;
    
    if (S_ISREG(path_stat.st_mode)) {
        // Target is a file
        analyze_file(&results[0], target);
        result_count = 1;
    } else if (S_ISDIR(path_stat.st_mode)) {
        // Target is a directory
        char file_list[MAX_RESULTS][MAX_PATH_LENGTH];
        int file_count = scan_directory(target, file_list, MAX_RESULTS);
        
        printf("Found %d C/C++ files to analyze\n", file_count);
        
        for (int i = 0; i < file_count; i++) {
            printf("Analyzing %s...\n", file_list[i]);
            analyze_file(&results[i], file_list[i]);
            result_count++;
        }
    } else {
        fprintf(stderr, "Error: '%s' is not a valid file or directory\n", target);
        free(results);
        return 1;
    }
    
    // Generate report
    if (strcmp(format, "json") == 0) {
        generate_json_report(results, result_count);
    } else {
        generate_text_report(results, result_count);
    }
    
    free(results);
    return 0;
}