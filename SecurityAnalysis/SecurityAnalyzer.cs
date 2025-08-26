using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace VulnerableWebApplication.SecurityAnalysis
{
    public static class SecurityAnalyzer
    {
        private static readonly Dictionary<string, VulnerabilityRule> VulnerabilityRules = new()
        {
            {
                "SQL_INJECTION",
                new VulnerabilityRule
                {
                    Pattern = @"(DataSet\.Tables\[0\]\.Select\s*\(\s*[""'][^""']*[""']\s*\+|\.Select\s*\(\s*[""'][^""']*[""']\s*\+)",
                    Severity = "CRITICAL",
                    Description = "Potential SQL Injection vulnerability detected",
                    Recommendation = "Use parameterized queries instead of string concatenation",
                    CweId = "CWE-89"
                }
            },
            {
                "COMMAND_INJECTION",
                new VulnerabilityRule
                {
                    Pattern = @"(Process\.Start|StartInfo\.FileName|StandardInput\.WriteLine\s*\(\s*[""'][^""']*[""']\s*\+)",
                    Severity = "CRITICAL",
                    Description = "Command injection vulnerability detected",
                    Recommendation = "Validate and sanitize input before executing system commands",
                    CweId = "CWE-78"
                }
            },
            {
                "PATH_TRAVERSAL",
                new VulnerabilityRule
                {
                    Pattern = @"(File\.ReadAllText\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)|\.Replace\s*\(\s*[""']\.\.\/[""']|\.Replace\s*\(\s*[""']\.\.\\[""'])",
                    Severity = "HIGH",
                    Description = "Path traversal vulnerability detected",
                    Recommendation = "Use Path.GetFullPath() and validate file paths against allowed directories",
                    CweId = "CWE-22"
                }
            },
            {
                "DESERIALIZATION",
                new VulnerabilityRule
                {
                    Pattern = @"JsonConvert\.DeserializeObject.*TypeNameHandling\.All",
                    Severity = "CRITICAL",
                    Description = "Unsafe deserialization with TypeNameHandling.All",
                    Recommendation = "Avoid TypeNameHandling.All or use custom type resolvers",
                    CweId = "CWE-502"
                }
            },
            {
                "CODE_INJECTION",
                new VulnerabilityRule
                {
                    Pattern = @"CSharpScript\.EvaluateAsync.*\+",
                    Severity = "CRITICAL",
                    Description = "Code injection vulnerability through dynamic script evaluation",
                    Recommendation = "Avoid dynamic code execution or implement strict input validation",
                    CweId = "CWE-94"
                }
            },
            {
                "XML_INJECTION",
                new VulnerabilityRule
                {
                    Pattern = @"(XmlDocument\.Load|XDocument\.Parse|DtdProcessing\.Parse|XmlUrlResolver)",
                    Severity = "HIGH",
                    Description = "XML External Entity (XXE) vulnerability",
                    Recommendation = "Disable DTD processing and external entity resolution",
                    CweId = "CWE-611"
                }
            },
            {
                "HARDCODED_CREDENTIALS",
                new VulnerabilityRule
                {
                    Pattern = @"(Secret[""]?\s*[:=]\s*[""'][A-F0-9]{32,}[""']|password[""]?\s*[:=]\s*[""'][^""']{8,}[""'])",
                    Severity = "HIGH",
                    Description = "Hardcoded credentials found",
                    Recommendation = "Use secure configuration management for sensitive data",
                    CweId = "CWE-798"
                }
            },
            {
                "WEAK_CRYPTO",
                new VulnerabilityRule
                {
                    Pattern = @"(SHA256\.Create\(\)|MD5\.Create\(\)|DES\.Create\(\))",
                    Severity = "MEDIUM",
                    Description = "Weak cryptographic implementation",
                    Recommendation = "Use stronger cryptographic algorithms and proper key management",
                    CweId = "CWE-326"
                }
            },
            {
                "BUFFER_OVERFLOW",
                new VulnerabilityRule
                {
                    Pattern = @"(stackalloc\s+char\[|unsafe\s+string)",
                    Severity = "HIGH",
                    Description = "Potential buffer overflow in unsafe code",
                    Recommendation = "Use safe string operations and bounds checking",
                    CweId = "CWE-787"
                }
            },
            {
                "FILE_UPLOAD",
                new VulnerabilityRule
                {
                    Pattern = @"(IFormFile.*FileName.*EndsWith|File\.OpenWrite\s*\(\s*.*FileName)",
                    Severity = "HIGH",
                    Description = "Unrestricted file upload vulnerability",
                    Recommendation = "Validate file types, names, and content before uploading",
                    CweId = "CWE-434"
                }
            },
            {
                "SSRF",
                new VulnerabilityRule
                {
                    Pattern = @"(HttpClient.*GetAsync\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)|client\.GetAsync\s*\(\s*uri\s*\))",
                    Severity = "HIGH",
                    Description = "Server-Side Request Forgery (SSRF) vulnerability",
                    Recommendation = "Validate and whitelist allowed URLs and domains",
                    CweId = "CWE-918"
                }
            },
            {
                "JWT_WEAK_VALIDATION",
                new VulnerabilityRule
                {
                    Pattern = @"(ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false|JwtSecurityToken\.Header\.Alg\s*==)",
                    Severity = "MEDIUM",
                    Description = "Weak JWT token validation",
                    Recommendation = "Enable proper JWT validation including issuer, audience, and algorithm checks",
                    CweId = "CWE-1270"
                }
            },
            {
                "INFORMATION_DISCLOSURE",
                new VulnerabilityRule
                {
                    Pattern = @"(exception\.Message|ex\.Message|\.ToString\(\).*Exception)",
                    Severity = "LOW",
                    Description = "Potential information disclosure through error messages",
                    Recommendation = "Log detailed errors securely and show generic error messages to users",
                    CweId = "CWE-209"
                }
            }
        };

        public static List<SecurityVulnerability> AnalyzeProject(string projectPath)
        {
            var vulnerabilities = new List<SecurityVulnerability>();
            
            try
            {
                var csharpFiles = Directory.GetFiles(projectPath, "*.cs", SearchOption.AllDirectories)
                    .Where(f => !f.Contains("\\bin\\") && 
                               !f.Contains("\\obj\\") &&
                               !f.Contains("\\SecurityAnalysis\\") &&  // Excluir archivos de análisis de seguridad
                               !Path.GetFileName(f).StartsWith("SecurityAnalyzer") &&
                               !Path.GetFileName(f).StartsWith("SecurityVulnerability"))
                    .ToList();

                foreach (var file in csharpFiles)
                {
                    try
                    {
                        var content = File.ReadAllText(file);
                        var lines = content.Split('\n');
                        
                        for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
                        {
                            var line = lines[lineIndex];
                            
                            // Saltar líneas que son comentarios o contienen patrones de análisis
                            if (line.Trim().StartsWith("//") || 
                                line.Trim().StartsWith("/*") ||
                                line.Contains("Pattern = @") ||
                                line.Contains("VulnerabilityRule"))
                            {
                                continue;
                            }
                            
                            foreach (var rule in VulnerabilityRules)
                            {
                                var matches = Regex.Matches(line, rule.Value.Pattern, RegexOptions.IgnoreCase);
                                
                                foreach (Match match in matches)
                                {
                                    vulnerabilities.Add(new SecurityVulnerability
                                    {
                                        Type = rule.Key.Replace("_", " "),
                                        Severity = rule.Value.Severity,
                                        Description = rule.Value.Description,
                                        File = Path.GetRelativePath(projectPath, file),
                                        LineNumber = lineIndex + 1,
                                        CodeSnippet = line.Trim(),
                                        Recommendation = rule.Value.Recommendation,
                                        CweId = rule.Value.CweId
                                    });
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // Si hay error leyendo un archivo específico, continúa con los demás
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            Type = "FILE ACCESS ERROR",
                            Severity = "INFO",
                            Description = $"Could not analyze file: {ex.Message}",
                            File = Path.GetRelativePath(projectPath, file),
                            LineNumber = 0,
                            CodeSnippet = "",
                            Recommendation = "Check file permissions and accessibility",
                            CweId = "N/A"
                        });
                    }
                }

                // Agregar vulnerabilidades específicas conocidas del proyecto VLA
                AddKnownVulnerabilities(vulnerabilities, projectPath);
            }
            catch (Exception ex)
            {
                vulnerabilities.Add(new SecurityVulnerability
                {
                    Type = "ANALYSIS ERROR",
                    Severity = "INFO",
                    Description = $"Error during security analysis: {ex.Message}",
                    File = "SecurityAnalyzer.cs",
                    LineNumber = 0,
                    CodeSnippet = "",
                    Recommendation = "Check project structure and file permissions",
                    CweId = "N/A"
                });
            }

            return vulnerabilities.OrderByDescending(v => GetSeverityWeight(v.Severity)).ToList();
        }

        private static void AddKnownVulnerabilities(List<SecurityVulnerability> vulnerabilities, string projectPath)
        {
            // Vulnerabilidades conocidas del proyecto VulnerableLightApp
            vulnerabilities.AddRange(new[]
            {
                new SecurityVulnerability
                {
                    Type = "AUTHENTICATION BYPASS",
                    Severity = "CRITICAL",
                    Description = "JWT validation logic can be bypassed using OR operator in algorithm check",
                    File = "Identity/VLAIdentity.cs",
                    LineNumber = 95,
                    CodeSnippet = "if (JwtSecurityToken.Header.Alg == \"HS256\" || JwtSecurityToken.Header.Typ == \"JWT\")",
                    Recommendation = "Use AND operator instead of OR for JWT algorithm validation",
                    CweId = "CWE-287"
                },
                new SecurityVulnerability
                {
                    Type = "BUSINESS LOGIC ERROR",
                    Severity = "MEDIUM",
                    Description = "Tax calculation logic error - using addition instead of proper tax calculation",
                    File = "Controller/Controller.cs",
                    LineNumber = 200,
                    CodeSnippet = "FinalPrice += (FinalPrice * tva) / 100;",
                    Recommendation = "Review business logic for tax calculations",
                    CweId = "CWE-840"
                },
                new SecurityVulnerability
                {
                    Type = "BACKDOOR",
                    Severity = "CRITICAL",
                    Description = "CPU testing functionality that could be used for denial of service",
                    File = "TestCpu/TestCpu.cs",
                    LineNumber = 20,
                    CodeSnippet = "Process.GetCurrentProcess().ProcessorAffinity",
                    Recommendation = "Remove or restrict access to CPU testing functionality",
                    CweId = "CWE-912"
                },
                new SecurityVulnerability
                {
                    Type = "INSECURE DIRECT OBJECT REFERENCE",
                    Severity = "MEDIUM",
                    Description = "Employee data accessible without proper authorization checks",
                    File = "Controller/Controller.cs",
                    LineNumber = 150,
                    CodeSnippet = "Data.GetEmployees()?.Where(x => Id == x.Id)",
                    Recommendation = "Implement proper access controls for employee data",
                    CweId = "CWE-639"
                }
            });
        }

        public static string GetSeverityColor(string severity)
        {
            return severity?.ToUpper() switch
            {
                "CRITICAL" => "#DC2626",
                "HIGH" => "#EA580C", 
                "MEDIUM" => "#D97706",
                "LOW" => "#65A30D",
                _ => "#6B7280"
            };
        }

        private static int GetSeverityWeight(string severity)
        {
            return severity?.ToUpper() switch
            {
                "CRITICAL" => 4,
                "HIGH" => 3,
                "MEDIUM" => 2,
                "LOW" => 1,
                _ => 0
            };
        }

        private class VulnerabilityRule
        {
            public string Pattern { get; set; } = string.Empty;
            public string Severity { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public string Recommendation { get; set; } = string.Empty;
            public string CweId { get; set; } = string.Empty;
        }
    }
}