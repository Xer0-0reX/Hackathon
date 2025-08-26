<%@ Page Title="Security Analysis" Language="C#" MasterPageFile="~/Resources/Master-Pages/Site.Master" AutoEventWireup="true" CodeBehind="SecurityAnalysis.aspx.cs" Inherits="OWASP.WebGoat.NET.SecurityAnalysis" %>

<asp:Content ID="Content1" ContentPlaceHolderID="HeadContentPlaceHolder" runat="server">
    <style>
        .vulnerability-container {
            margin: 20px 0;
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
        }
        
        .vulnerability-item {
            background: white;
            border-left: 5px solid #ccc;
            margin: 15px 0;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .severity-critical { border-left-color: #DC2626; }
        .severity-high { border-left-color: #EA580C; }
        .severity-medium { border-left-color: #D97706; }
        .severity-low { border-left-color: #65A30D; }
        
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .vulnerability-type {
            font-weight: bold;
            font-size: 1.1em;
            color: #1f2937;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
        }
        
        .vulnerability-description {
            color: #4b5563;
            margin: 10px 0;
        }
        
        .vulnerability-location {
            background: #f3f4f6;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }
        
        .vulnerability-code {
            background: #1f2937;
            color: #f9fafb;
            padding: 12px;
            border-radius: 4px;
            font-family: monospace;
            margin: 10px 0;
            overflow-x: auto;
        }
        
        .vulnerability-recommendation {
            background: #ecfdf5;
            border: 1px solid #a7f3d0;
            padding: 12px;
            border-radius: 4px;
            margin: 10px 0;
        }
        
        .stats-container {
            display: flex;
            gap: 20px;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        
        .stat-item {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            flex: 1;
            min-width: 150px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: #6b7280;
            font-size: 0.9em;
        }
        
        .refresh-btn {
            background: #3b82f6;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            margin-bottom: 20px;
        }
        
        .refresh-btn:hover {
            background: #2563eb;
        }
        
        .no-vulnerabilities {
            text-align: center;
            padding: 40px;
            color: #6b7280;
        }
        
        .analysis-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .analysis-title {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: bold;
        }
        
        .analysis-subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
    </style>
</asp:Content>

<asp:Content ID="Content2" ContentPlaceHolderID="HelpContentPlaceholder" runat="server">
    <p>
        <strong>Security Analysis Tool</strong><br />
        This tool automatically scans the WebGoat.NET source code for common security vulnerabilities including:
        <ul>
            <li>SQL Injection vulnerabilities</li>
            <li>Cross-Site Scripting (XSS) issues</li>
            <li>Command Injection problems</li>
            <li>Weak cryptography usage</li>
            <li>Hardcoded credentials</li>
            <li>Path traversal vulnerabilities</li>
            <li>And many more security issues...</li>
        </ul>
        Click "Refresh Analysis" to scan the codebase and view detailed security recommendations.
    </p>
</asp:Content>

<asp:Content ID="Content3" ContentPlaceHolderID="BodyContentPlaceholder" runat="server">
    <div class="analysis-header">
        <div class="analysis-title">Security Analysis</div>
        <div class="analysis-subtitle">Vulnerability Detection & Code Analysis</div>
    </div>

    <asp:Button ID="btnRefresh" runat="server" Text="Refresh Analysis" 
                CssClass="refresh-btn" OnClick="btnRefresh_Click" />
    
    <asp:Panel ID="StatsPanel" runat="server" CssClass="stats-container">
        <div class="stat-item">
            <div class="stat-number" style="color: #DC2626;">
                <asp:Literal ID="litCritical" runat="server" Text="0" />
            </div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-item">
            <div class="stat-number" style="color: #EA580C;">
                <asp:Literal ID="litHigh" runat="server" Text="0" />
            </div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-item">
            <div class="stat-number" style="color: #D97706;">
                <asp:Literal ID="litMedium" runat="server" Text="0" />
            </div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="stat-item">
            <div class="stat-number" style="color: #65A30D;">
                <asp:Literal ID="litLow" runat="server" Text="0" />
            </div>
            <div class="stat-label">Low</div>
        </div>
        <div class="stat-item">
            <div class="stat-number" style="color: #3b82f6;">
                <asp:Literal ID="litTotal" runat="server" Text="0" />
            </div>
            <div class="stat-label">Total Issues</div>
        </div>
    </asp:Panel>

    <div class="vulnerability-container">
        <asp:Repeater ID="VulnerabilityRepeater" runat="server">
            <HeaderTemplate>
                <h3>Detected Vulnerabilities</h3>
            </HeaderTemplate>
            <ItemTemplate>
                <div class="vulnerability-item severity-<%# Eval("Severity").ToString().ToLower() %>">
                    <div class="vulnerability-header">
                        <span class="vulnerability-type"><%# Eval("Type") %></span>
                        <span class="severity-badge" style="background-color: <%# GetSeverityColor(Eval("Severity").ToString()) %>">
                            <%# Eval("Severity") %>
                        </span>
                    </div>
                    
                    <div class="vulnerability-description">
                        Description: <%# Eval("Description") %>
                    </div>
                    
                    <div class="vulnerability-location">
                        File: <%# Eval("File") %> | Line: <%# Eval("LineNumber") %>
                    </div>
                    
                    <%# !string.IsNullOrEmpty(Eval("CodeSnippet").ToString()) ? 
                        "<div class=\"vulnerability-code\">Code: " + Server.HtmlEncode(Eval("CodeSnippet").ToString()) + "</div>" : "" %>
                    
                    <div class="vulnerability-recommendation">
                        <strong>Recommendation:</strong> <%# Eval("Recommendation") %>
                    </div>
                </div>
            </ItemTemplate>
            <FooterTemplate>
                <asp:Panel ID="NoVulnerabilitiesPanel" runat="server" CssClass="no-vulnerabilities">
                    <h3>Analysis Complete</h3>
                    <p>Security scan has finished. Check the results above.</p>
                </asp:Panel>
            </FooterTemplate>
        </asp:Repeater>
    </div>
</asp:Content>