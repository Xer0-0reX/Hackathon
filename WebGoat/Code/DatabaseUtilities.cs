using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Data;
using System.IO;
using System.Text;
using System.Configuration;

namespace OWASP.WebGoat.NET
{
	public class DatabaseUtilities
	{
		// Datos mockeados para mantener las vulnerabilidades sin necesidad de BD
		private static Dictionary<string, string> mockUsers = new Dictionary<string, string>
		{
			{"1", "admin@webgoat.com"},
			{"2", "user@webgoat.com"},
			{"3", "test@webgoat.com"},
			{"4", "guest@webgoat.com"}
		};

		private static List<Dictionary<string, object>> mockMailingList = new List<Dictionary<string, object>>
		{
			new Dictionary<string, object> { {"FirstName", "John"}, {"LastName", "Admin"}, {"Email", "admin@webgoat.com"} },
			new Dictionary<string, object> { {"FirstName", "Jane"}, {"LastName", "User"}, {"Email", "user@webgoat.com"} },
			new Dictionary<string, object> { {"FirstName", "Test"}, {"LastName", "Account"}, {"Email", "test@webgoat.com"} }
		};

		private static List<Dictionary<string, object>> mockPostings = new List<Dictionary<string, object>>
		{
			new Dictionary<string, object> { {"PostingID", 1}, {"Title", "Welcome Post"}, {"Email", "admin@webgoat.com"}, {"Message", "Welcome to WebGoat!"} },
			new Dictionary<string, object> { {"PostingID", 2}, {"Title", "Test Message"}, {"Email", "user@webgoat.com"}, {"Message", "This is a test message with <script>alert('XSS')</script>"} },
			new Dictionary<string, object> { {"PostingID", 3}, {"Title", "Sample Post"}, {"Email", "test@webgoat.com"}, {"Message", "Just a sample posting"} }
		};
		
		public Boolean RecreateGoatDB ()
		{
			// Simular éxito sin crear archivos
			return true;			
		}
		
		private string DoNonQuery (String SQL)
		{
			// Simular ejecución exitosa de SQL - mantener vulnerabilidad mostrando el SQL
			return "<br/>SQL Executed (Mocked): " + SQL;
		}
		
		private string DoScalar (String SQL)
		{
			// Simular consultas escalares comunes
			if (SQL.ToLower().Contains("select email from userlist"))
			{
				// Extraer userid del SQL (mantener vulnerabilidad de SQL injection)
				var parts = SQL.Split('\'');
				if (parts.Length >= 2)
				{
					string userid = parts[1];
					return mockUsers.ContainsKey(userid) ? mockUsers[userid] : null;
				}
			}
			return "mocked_result";
		}
		
		private DataTable DoQuery (string SQL)
		{
			DataTable dt = new DataTable();
			
			// Simular diferentes tipos de consultas manteniendo vulnerabilidades
			if (SQL.ToLower().Contains("mailinglist"))
			{
				dt.Columns.Add("FirstName", typeof(string));
				dt.Columns.Add("LastName", typeof(string));
				dt.Columns.Add("Email", typeof(string));
				
				// Simular búsqueda por email (mantener SQL injection vulnerability)
				foreach (var item in mockMailingList)
				{
					if (SQL.ToLower().Contains("where") && SQL.ToLower().Contains("email"))
					{
						// Extraer email del SQL de forma vulnerable
						var emailStart = SQL.ToLower().IndexOf("email = '") + 9;
						if (emailStart > 8)
						{
							var emailEnd = SQL.IndexOf("'", emailStart);
							if (emailEnd > emailStart)
							{
								string searchEmail = SQL.Substring(emailStart, emailEnd - emailStart);
								if (item["Email"].ToString().Contains(searchEmail))
								{
									dt.Rows.Add(item["FirstName"], item["LastName"], item["Email"]);
								}
							}
						}
					}
					else
					{
						dt.Rows.Add(item["FirstName"], item["LastName"], item["Email"]);
					}
				}
			}
			else if (SQL.ToLower().Contains("postings"))
			{
				if (SQL.ToLower().Contains("select title, email, message"))
				{
					dt.Columns.Add("Title", typeof(string));
					dt.Columns.Add("Email", typeof(string));
					dt.Columns.Add("Message", typeof(string));
					
					foreach (var item in mockPostings)
					{
						if (SQL.ToLower().Contains("where postingid="))
						{
							// Extraer ID del SQL (mantener vulnerabilidad)
							var idPart = SQL.Substring(SQL.ToLower().IndexOf("postingid=") + 10).Trim();
							if (int.TryParse(idPart, out int id) && (int)item["PostingID"] == id)
							{
								dt.Rows.Add(item["Title"], item["Email"], item["Message"]);
							}
						}
						else
						{
							dt.Rows.Add(item["Title"], item["Email"], item["Message"]);
						}
					}
				}
				else if (SQL.ToLower().Contains("select postingid, title"))
				{
					dt.Columns.Add("PostingID", typeof(int));
					dt.Columns.Add("Title", typeof(string));
					
					foreach (var item in mockPostings)
					{
						dt.Rows.Add(item["PostingID"], item["Title"]);
					}
				}
			}
			
			return dt;
		}
		
		public string GetEmailByUserID (string userid)
		{
			if (userid.Length > 4)
				userid = userid.Substring (0, 4);
			
			// Simular consulta SQL vulnerable
			String SQL = "SELECT Email FROM UserList WHERE UserID = '" + userid + "'";
			String output = DoScalar (SQL);
			
			if (output != null && output != "mocked_result")
				return output;
			else 
				return "Email for userid: " + userid + " not found<p/>";
		}

		public DataTable GetMailingListInfoByEmailAddress (string email)
		{
			// Mantener vulnerabilidad de SQL injection
			string sql = "SELECT FirstName, LastName, Email FROM MailingList where Email = '" + email + "'";
			DataTable result = DoQuery (sql);
			return result;
		}

		public string AddToMailingList (string first, string last, string email)
		{
			// Simular inserción manteniendo la vulnerabilidad visible
			string sql = "insert into mailinglist (firstname, lastname, email) values ('" + first + "', '" + last + "', '" + email + "')";
			
			// Agregar a la lista mockeada
			mockMailingList.Add(new Dictionary<string, object> { 
				{"FirstName", first}, 
				{"LastName", last}, 
				{"Email", email} 
			});
			
			string result = DoNonQuery (sql);
			return result;
		}

		public DataTable GetAllPostings ()
		{
			string sql = "SELECT Title, Email, Message FROM Postings";
			DataTable result = DoQuery (sql);
			return result;
		}

		public string AddNewPosting (String title, String email, String message)
		{
			// Mantener vulnerabilidad de SQL injection
			string sql = "insert into Postings(title, email, message) values ('" + title + "','" + email + "','" + message + "')";
			
			// Agregar a la lista mockeada
			int newId = mockPostings.Count + 1;
			mockPostings.Add(new Dictionary<string, object> { 
				{"PostingID", newId},
				{"Title", title}, 
				{"Email", email}, 
				{"Message", message} 
			});
			
			string result = DoNonQuery (sql);
			return result;
		}

		public DataTable GetPostingLinks ()
		{
			string sql = "SELECT PostingID, Title FROM Postings";
			DataTable result = DoQuery (sql);
			return result;
		}
		
		public DataTable GetPostingByID(int id)
		{
			// Mantener vulnerabilidad de SQL injection
			string sql = "SELECT Title, Email, Message FROM Postings where PostingID=" + id;
			DataTable result = DoQuery (sql);
			return result;
		}
		
		// Métodos de conexión eliminados ya que no los necesitamos
	}
}