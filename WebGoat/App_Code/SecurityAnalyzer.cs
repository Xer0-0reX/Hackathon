using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Web;
using System.Linq;

namespace OWASP.WebGoat.NET.App_Code
{
    public class SecurityVulnerability
    {
        public string Type { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public string File { get; set; }
        public int LineNumber { get; set; }
        public string CodeSnippet { get; set; }
        public string Recommendation { get; set; }
    }

    public class SecurityAnalyzer
    {
        // Lista de archivos que deben ser excluidos del análisis
        private static readonly HashSet<string> ExcludedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "SecurityAnalyzer.cs",
            "SecurityAnalysis.aspx",
            "SecurityAnalysis.aspx.cs",
            "SecurityAnalysis.aspx.designer.cs"
        };

        private static readonly Dictionary<string, VulnerabilityPattern> VulnerabilityPatterns = 
            new Dictionary<string, VulnerabilityPattern>
        {
            {
                "SQL_INJECTION",
                new VulnerabilityPattern
                {
                    Pattern = @"\b(SELECT|INSERT|UPDATE|DELETE)\b[^=]*\+[^=]*['""]",
                    Type = "SQL Injection",
                    Severity = "HIGH",
                    Description = "Possible SQL injection vulnerability detected - string concatenation in SQL query",
                    Recommendation = "Use parameterized queries or stored procedures instead of string concatenation"
                }
            },
            {
                "XSS_RESPONSE_WRITE",
                new VulnerabilityPattern
                {
                    Pattern = @"Response\.Write\s*\(\s*Request\.",
                    Type = "Cross-Site Scripting (XSS)",
                    Severity = "HIGH", 
                    Description = "Potential XSS vulnerability - user input directly written to response",
                    Recommendation = "Encode user input using Server.HtmlEncode() or AntiXSS library"
                }
            },
            {
                "XSS_LITERAL_CONTROL",
                new VulnerabilityPattern
                {
                    Pattern = @"\.Text\s*=\s*Request\.",
                    Type = "Cross-Site Scripting (XSS)",
                    Severity = "HIGH",
                    Description = "Potential XSS vulnerability - user input assigned to control text",
                    Recommendation = "Encode user input before assignment or use safe controls"
                }
            },
            {
                "COMMAND_INJECTION",
                new VulnerabilityPattern
                {
                    Pattern = @"Process\.Start\s*\(\s*[^)]*Request\.",
                    Type = "Command Injection",
                    Severity = "CRITICAL",
                    Description = "Critical command injection vulnerability - user input in process execution",
                    Recommendation = "Validate and sanitize all user input, avoid executing system commands with user data"
                }
            },
            {
                "PATH_TRAVERSAL",
                new VulnerabilityPattern
                {
                    Pattern = @"(File\.Open|File\.Read|FileStream).*Request\.",
                    Type = "Path Traversal",
                    Severity = "HIGH",
                    Description = "Path traversal vulnerability - user input in file operations",
                    Recommendation = "Validate file paths and use Path.GetFileName() to prevent directory traversal"
                }
            },
            {
                "WEAK_CRYPTO",
                new VulnerabilityPattern
                {
                    Pattern = @"(MD5|SHA1)(?!.*HMAC)",
                    Type = "Weak Cryptography",
                    Severity = "MEDIUM",
                    Description = "Weak cryptographic algorithm detected",
                    Recommendation = "Use stronger algorithms like SHA-256 or SHA-512"
                }
            },
            {
                "HARDCODED_PASSWORD",
                new VulnerabilityPattern
                {
                    Pattern = @"(password|pwd)\s*=\s*['""][^'""]{3,}['""]",
                    Type = "Hardcoded Credentials",
                    Severity = "HIGH",
                    Description = "Hardcoded password detected in source code",
                    Recommendation = "Store passwords in configuration files or secure vaults"
                }
            },
            {
                "INSECURE_RANDOM",
                new VulnerabilityPattern
                {
                    Pattern = @"new Random\(\)",
                    Type = "Weak Random Number Generation",
                    Severity = "MEDIUM",
                    Description = "Insecure random number generation for security purposes",
                    Recommendation = "Use RNGCryptoServiceProvider for cryptographic random numbers"
                }
            },
            {
                "DEBUG_INFO",
                new VulnerabilityPattern
                {
                    Pattern = @"debug\s*=\s*['""]true['""]",
                    Type = "Information Disclosure",
                    Severity = "LOW",
                    Description = "Debug mode enabled - may expose sensitive information",
                    Recommendation = "Disable debug mode in production environment"
                }
            },
            {
                "VIEWSTATE_DISABLED",
                new VulnerabilityPattern
                {
                    Pattern = @"EnableViewStateMac\s*=\s*['""]?false['""]?",
                    Type = "ViewState Tampering",
                    Severity = "MEDIUM",
                    Description = "ViewState MAC validation disabled",
                    Recommendation = "Enable ViewState MAC validation to prevent tampering"
                }
            }
        };

        public static List<SecurityVulnerability> AnalyzeProject(string projectPath)
        {
            var vulnerabilities = new List<SecurityVulnerability>();
            
            try
            {
                // Analizar archivos .cs (excluyendo archivos del escáner)
                var csFiles = Directory.GetFiles(projectPath, "*.cs", SearchOption.AllDirectories)
                    .Where(file => !ExcludedFiles.Contains(Path.GetFileName(file)));
                foreach (var file in csFiles)
                {
                    vulnerabilities.AddRange(AnalyzeFile(file));
                }

                // Analizar archivos .aspx (excluyendo páginas del escáner)
                var aspxFiles = Directory.GetFiles(projectPath, "*.aspx", SearchOption.AllDirectories)
                    .Where(file => !ExcludedFiles.Contains(Path.GetFileName(file)));
                foreach (var file in aspxFiles)
                {
                    vulnerabilities.AddRange(AnalyzeFile(file));
                }

                // Analizar archivos de configuración
                var configFiles = Directory.GetFiles(projectPath, "*.config", SearchOption.AllDirectories);
                foreach (var file in configFiles)
                {
                    vulnerabilities.AddRange(AnalyzeFile(file));
                }
            }
            catch (Exception ex)
            {
                // En caso de error, agregar al menos una vulnerabilidad de ejemplo
                vulnerabilities.Add(new SecurityVulnerability
                {
                    Type = "Analysis Error",
                    Severity = "INFO",
                    Description = "Error during security analysis: " + ex.Message,
                    File = "SecurityAnalyzer",
                    LineNumber = 0,
                    CodeSnippet = "",
                    Recommendation = "Check file permissions and project structure"
                });
            }

            return vulnerabilities.OrderByDescending(v => GetSeverityWeight(v.Severity)).ToList();
        }

        private static List<SecurityVulnerability> AnalyzeFile(string filePath)
        {
            var vulnerabilities = new List<SecurityVulnerability>();
            
            try
            {
                var fileName = Path.GetFileName(filePath);
                
                // Verificar si el archivo está en la lista de excluidos
                if (ExcludedFiles.Contains(fileName))
                {
                    return vulnerabilities; // Retornar lista vacía para archivos excluidos
                }
                
                var lines = File.ReadAllLines(filePath);

                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    
                    // Saltar líneas que contienen definiciones de patrones de vulnerabilidades
                    if (line.Contains("Pattern = @") || line.Contains("VulnerabilityPattern"))
                    {
                        continue;
                    }
                    
                    foreach (var pattern in VulnerabilityPatterns)
                    {
                        if (Regex.IsMatch(line, pattern.Value.Pattern, RegexOptions.IgnoreCase))
                        {
                            vulnerabilities.Add(new SecurityVulnerability
                            {
                                Type = pattern.Value.Type,
                                Severity = pattern.Value.Severity,
                                Description = pattern.Value.Description,
                                File = fileName,
                                LineNumber = i + 1,
                                CodeSnippet = line.Trim(),
                                Recommendation = pattern.Value.Recommendation
                            });
                        }
                    }
                }
            }
            catch
            {
                // Ignorar errores de archivos individuales
            }

            return vulnerabilities;
        }

        private static int GetSeverityWeight(string severity)
        {
            switch (severity.ToUpper())
            {
                case "CRITICAL": return 4;
                case "HIGH": return 3;
                case "MEDIUM": return 2;
                case "LOW": return 1;
                default: return 0;
            }
        }

        public static string GetSeverityColor(string severity)
        {
            switch (severity.ToUpper())
            {
                case "CRITICAL": return "#DC2626"; // Red
                case "HIGH": return "#EA580C"; // Orange
                case "MEDIUM": return "#D97706"; // Amber
                case "LOW": return "#65A30D"; // Green
                default: return "#6B7280"; // Gray
            }
        }
    }

    public class VulnerabilityPattern
    {
        public string Pattern { get; set; }
        public string Type { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public string Recommendation { get; set; }
    }
}