using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.UI;
using System.Web.UI.WebControls;
using OWASP.WebGoat.NET.App_Code;

namespace OWASP.WebGoat.NET
{
    public partial class SecurityAnalysis : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                RunSecurityAnalysis();
            }
        }

        protected void btnRefresh_Click(object sender, EventArgs e)
        {
            RunSecurityAnalysis();
        }

        private void RunSecurityAnalysis()
        {
            try
            {
                // Obtener la ruta del proyecto
                string projectPath = Server.MapPath("~/");
                
                // Ejecutar análisis de seguridad
                var vulnerabilities = SecurityAnalyzer.AnalyzeProject(projectPath);
                
                // Actualizar estadísticas
                UpdateStatistics(vulnerabilities);
                
                // Vincular datos al Repeater
                VulnerabilityRepeater.DataSource = vulnerabilities;
                VulnerabilityRepeater.DataBind();
            }
            catch (Exception ex)
            {
                // En caso de error, mostrar una vulnerabilidad de ejemplo
                var errorVulnerability = new List<SecurityVulnerability>
                {
                    new SecurityVulnerability
                    {
                        Type = "Analysis Error",
                        Severity = "INFO",
                        Description = "Error during security analysis: " + ex.Message,
                        File = "SecurityAnalysis.aspx.cs",
                        LineNumber = 0,
                        CodeSnippet = "",
                        Recommendation = "Check file permissions and project structure"
                    }
                };
                
                VulnerabilityRepeater.DataSource = errorVulnerability;
                VulnerabilityRepeater.DataBind();
                
                UpdateStatistics(errorVulnerability);
            }
        }

        private void UpdateStatistics(List<SecurityVulnerability> vulnerabilities)
        {
            int critical = vulnerabilities.Count(v => v.Severity.ToUpper() == "CRITICAL");
            int high = vulnerabilities.Count(v => v.Severity.ToUpper() == "HIGH");
            int medium = vulnerabilities.Count(v => v.Severity.ToUpper() == "MEDIUM");
            int low = vulnerabilities.Count(v => v.Severity.ToUpper() == "LOW");
            int total = vulnerabilities.Count;

            litCritical.Text = critical.ToString();
            litHigh.Text = high.ToString();
            litMedium.Text = medium.ToString();
            litLow.Text = low.ToString();
            litTotal.Text = total.ToString();
        }

        protected string GetSeverityColor(string severity)
        {
            return SecurityAnalyzer.GetSeverityColor(severity);
        }
    }
}