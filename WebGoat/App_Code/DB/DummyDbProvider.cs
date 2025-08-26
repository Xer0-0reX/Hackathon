using System;
using System.Data;
using System.Collections.Generic;

namespace OWASP.WebGoat.NET.App_Code.DB
{
    public class DummyDbProvider : IDbProvider
    {
        // Constantes para evitar repetir strings literales
        private const string ADMIN_EMAIL = "admin@webgoat.com";
        private const string USER_EMAIL = "user@webgoat.com";
        private const string TEST_EMAIL = "test@webgoat.com";
        private const string GUEST_EMAIL = "guest@webgoat.com";
        private const string COINS = "Coins";
        private const string EMAIL_COLUMN = "email";
        private const string PRODUCTS_TABLE = "products";
        private const string COMMENTS_TABLE = "comments";
        private const string CATEGORIES_TABLE = "categories";
        
        public bool TestConnection()
        {
            return true;
        }

        public ConfigFile DbConfigFile
        {
            get; set;
        }
        
        public DataSet GetCatalogData()
        {
            DataSet ds = new DataSet();
            DataTable dt = new DataTable();
            dt.Columns.Add("productCode", typeof(string));
            dt.Columns.Add("productName", typeof(string));
            dt.Columns.Add("productLine", typeof(string));
            dt.Columns.Add("productScale", typeof(string));
            dt.Columns.Add("productVendor", typeof(string));
            dt.Columns.Add("productDescription", typeof(string));
            dt.Columns.Add("quantityInStock", typeof(int));
            dt.Columns.Add("buyPrice", typeof(decimal));
            dt.Columns.Add("MSRP", typeof(decimal));
            
            dt.Rows.Add("COIN001", "American Gold Eagle", COINS, "1:1", "US Mint", "1 oz Gold Eagle", 50, 1800.00, 2000.00);
            dt.Rows.Add("COIN002", "Canadian Maple Leaf", COINS, "1:1", "Royal Canadian Mint", "1 oz Silver Maple", 100, 25.00, 30.00);
            dt.Rows.Add("COIN003", "Austrian Philharmonic", COINS, "1:1", "Austrian Mint", "1 oz Gold Philharmonic", 25, 1750.00, 1950.00);
            dt.Rows.Add("COIN004", "Chinese Panda", COINS, "1:1", "China Mint", "1 oz Silver Panda", 75, 35.00, 45.00);
            
            ds.Tables.Add(dt);
            return ds;
        }

        public bool IsValidCustomerLogin(string email, string password)
        {
            // Mantener vulnerabilidad: permitir algunos logins para testing
            var validUsers = new Dictionary<string, string>
            {
                {ADMIN_EMAIL, "admin"},
                {USER_EMAIL, "password"},
                {TEST_EMAIL, "test123"},
                {GUEST_EMAIL, "guest"}
            };
            
            return validUsers.ContainsKey(email) && validUsers[email] == password;
        }

        public bool RecreateGoatDb()
        {
            return true; // Simular éxito
        }

        public string GetCustomerEmail(string customerNumber)
        {
            var customers = new Dictionary<string, string>
            {
                {"1", ADMIN_EMAIL},
                {"2", USER_EMAIL},
                {"3", TEST_EMAIL},
                {"4", GUEST_EMAIL}
            };
            
            return customers.ContainsKey(customerNumber) ? customers[customerNumber] : "unknown@webgoat.com";
        }

        public DataSet GetCustomerDetails(string customerNumber)
        {
            DataSet ds = new DataSet();
            DataTable dt = new DataTable();
            dt.Columns.Add("customerNumber", typeof(int));
            dt.Columns.Add("customerName", typeof(string));
            dt.Columns.Add("contactLastName", typeof(string));
            dt.Columns.Add("contactFirstName", typeof(string));
            dt.Columns.Add("phone", typeof(string));
            dt.Columns.Add("addressLine1", typeof(string));
            dt.Columns.Add("city", typeof(string));
            dt.Columns.Add("state", typeof(string));
            dt.Columns.Add("postalCode", typeof(string));
            dt.Columns.Add("country", typeof(string));
            dt.Columns.Add("creditLimit", typeof(decimal));
            
            if (customerNumber == "1")
                dt.Rows.Add(1, "WebGoat Admin", "Admin", "System", "555-0001", "123 Admin St", "AdminCity", "AC", "12345", "USA", 10000.00);
            else if (customerNumber == "2")
                dt.Rows.Add(2, "Test User", "User", "Test", "555-0002", "456 User Ave", "UserTown", "UT", "67890", "USA", 5000.00);
            else
                dt.Rows.Add(int.Parse(customerNumber), "Unknown Customer", "Unknown", "User", "555-0000", "Unknown Address", "Unknown", "UK", "00000", "USA", 1000.00);
            
            ds.Tables.Add(dt);
            return ds;
        }

        public DataSet GetOffice(string city)
        {
            DataSet ds = new DataSet();
            DataTable dt = new DataTable();
            dt.Columns.Add("officeCode", typeof(string));
            dt.Columns.Add("city", typeof(string));
            dt.Columns.Add("phone", typeof(string));
            dt.Columns.Add("addressLine1", typeof(string));
            dt.Columns.Add("country", typeof(string));
            dt.Columns.Add("postalCode", typeof(string));
            
            // Simular datos para diferentes ciudades
            if (city.ToLower().Contains("new york"))
                dt.Rows.Add("1", "New York", "555-NYC-001", "123 Manhattan St", "USA", "10001");
            else if (city.ToLower().Contains("london"))
                dt.Rows.Add("2", "London", "44-20-1234", "456 Thames St", "UK", "SW1A 1AA");
            else
                dt.Rows.Add("3", city, "555-000-000", "Unknown Address", "Unknown Country", "00000");
            
            ds.Tables.Add(dt);
            return ds;
        }

        public DataSet GetComments(string productCode)
        {
            DataSet ds = new DataSet();
            DataTable dt = new DataTable();
            dt.Columns.Add("commentId", typeof(int));
            dt.Columns.Add("productCode", typeof(string));
            dt.Columns.Add(EMAIL_COLUMN, typeof(string));
            dt.Columns.Add("comment", typeof(string));
            dt.Columns.Add("dateCreated", typeof(DateTime));
            
            // Datos de ejemplo con algunos comentarios "vulnerables"
            dt.Rows.Add(1, productCode, "user1@test.com", "Great product! <script>alert('XSS')</script>", DateTime.Now.AddDays(-5));
            dt.Rows.Add(2, productCode, "user2@test.com", "Good quality coin", DateTime.Now.AddDays(-3));
            dt.Rows.Add(3, productCode, ADMIN_EMAIL, "This is a test comment", DateTime.Now.AddDays(-1));
            
            ds.Tables.Add(dt);
            return ds;
        }

        public string AddComment(string productCode, string email, string comment)
        {
            // Simular inserción exitosa - mantener vulnerabilidad permitiendo cualquier input
            return "Comment added successfully for product: " + productCode;
        }

        public string UpdateCustomerPassword(int customerNumber, string password)
        {
            return "Password updated successfully for customer: " + customerNumber;
        }

        public string[] GetSecurityQuestionAndAnswer(string email)
        {
            // Datos de ejemplo para preguntas de seguridad
            var questions = new Dictionary<string, string[]>
            {
                {ADMIN_EMAIL, new[] {"What is your pet's name?", "Fluffy"}},
                {USER_EMAIL, new[] {"What is your mother's maiden name?", "Smith"}},
                {TEST_EMAIL, new[] {"What city were you born in?", "TestCity"}}
            };
            
            return questions.ContainsKey(email) ? questions[email] : new[] {"What is your favorite color?", "Blue"};
        }

        public string GetPasswordByEmail(string email)
        {
            var passwords = new Dictionary<string, string>
            {
                {ADMIN_EMAIL, "admin"},
                {USER_EMAIL, "password"},
                {TEST_EMAIL, "test123"},
                {GUEST_EMAIL, "guest"}
            };
            
            return passwords.ContainsKey(email) ? passwords[email] : "default123";
        }

        public DataSet GetUsers()
        {
            DataSet ds = new DataSet();
            DataTable dt = new DataTable();
            dt.Columns.Add("userId", typeof(int));
            dt.Columns.Add("username", typeof(string));
            dt.Columns.Add(EMAIL_COLUMN, typeof(string));
            dt.Columns.Add("role", typeof(string));
            dt.Columns.Add("isActive", typeof(bool));
            
            dt.Rows.Add(1, "admin", ADMIN_EMAIL, "Administrator", true);
            dt.Rows.Add(2, "user", USER_EMAIL, "User", true);
            dt.Rows.Add(3, "test", TEST_EMAIL, "User", true);
            dt.Rows.Add(4, "guest", GUEST_EMAIL, "Guest", false);
            
            ds.Tables.Add(dt);
            return ds;
        }

        public DataSet GetOrders(int customerID)
        {
            DataSet ds = new DataSet();
            DataTable dt = new DataTable();
            dt.Columns.Add("orderNumber", typeof(int));
            dt.Columns.Add("orderDate", typeof(DateTime));
            dt.Columns.Add("requiredDate", typeof(DateTime));
            dt.Columns.Add("shippedDate", typeof(DateTime));
            dt.Columns.Add("status", typeof(string));
            dt.Columns.Add("customerNumber", typeof(int));
            
            dt.Rows.Add(1001, DateTime.Now.AddDays(-10), DateTime.Now.AddDays(-5), DateTime.Now.AddDays(-3), "Shipped", customerID);
            dt.Rows.Add(1002, DateTime.Now.AddDays(-5), DateTime.Now, null, "Processing", customerID);
            
            ds.Tables.Add(dt);
            return ds;
        }

        public DataSet GetProductDetails(string productCode)
        {
            DataSet ds = new DataSet();
            
            // Tabla de productos
            DataTable products = new DataTable(PRODUCTS_TABLE);
            products.Columns.Add("productCode", typeof(string));
            products.Columns.Add("productName", typeof(string));
            products.Columns.Add("productDescription", typeof(string));
            products.Columns.Add("buyPrice", typeof(decimal));
            products.Columns.Add("MSRP", typeof(decimal));
            
            products.Rows.Add(productCode, "Sample Product", "This is a sample product description", 100.00, 150.00);
            
            // Tabla de comentarios
            DataTable comments = new DataTable(COMMENTS_TABLE);
            comments.Columns.Add("commentId", typeof(int));
            comments.Columns.Add("productCode", typeof(string));
            comments.Columns.Add(EMAIL_COLUMN, typeof(string));
            comments.Columns.Add("comment", typeof(string));
            
            comments.Rows.Add(1, productCode, "user@test.com", "Great product!");
            comments.Rows.Add(2, productCode, "admin@test.com", "Excellent quality");
            
            ds.Tables.Add(products);
            ds.Tables.Add(comments);
            
            // Crear relación
            DataRelation dr = new DataRelation("prod_comments",
                ds.Tables[PRODUCTS_TABLE].Columns["productCode"],
                ds.Tables[COMMENTS_TABLE].Columns["productCode"],
                false);
            ds.Relations.Add(dr);
            
            return ds;
        }

        public DataSet GetOrderDetails(int orderNumber)
        {
            DataSet ds = new DataSet();
            DataTable dt = new DataTable();
            dt.Columns.Add("orderNumber", typeof(int));
            dt.Columns.Add("productCode", typeof(string));
            dt.Columns.Add("quantityOrdered", typeof(int));
            dt.Columns.Add("priceEach", typeof(decimal));
            dt.Columns.Add("orderLineNumber", typeof(int));
            
            dt.Rows.Add(orderNumber, "COIN001", 2, 1800.00, 1);
            dt.Rows.Add(orderNumber, "COIN002", 5, 25.00, 2);
            
            ds.Tables.Add(dt);
            return ds;
        }

        public DataSet GetPayments(int customerNumber)
        {
            DataSet ds = new DataSet();
            DataTable dt = new DataTable();
            dt.Columns.Add("customerNumber", typeof(int));
            dt.Columns.Add("checkNumber", typeof(string));
            dt.Columns.Add("paymentDate", typeof(DateTime));
            dt.Columns.Add("amount", typeof(decimal));
            
            dt.Rows.Add(customerNumber, "CHK001", DateTime.Now.AddDays(-10), 1000.00);
            dt.Rows.Add(customerNumber, "CHK002", DateTime.Now.AddDays(-5), 500.00);
            
            ds.Tables.Add(dt);
            return ds;
        }

        public DataSet GetProductsAndCategories()
        {
            return GetProductsAndCategories(0);
        }

        public DataSet GetProductsAndCategories(int catNumber)
        {
            DataSet ds = new DataSet();
            
            // Tabla de categorías
            DataTable categories = new DataTable(CATEGORIES_TABLE);
            categories.Columns.Add("catNumber", typeof(int));
            categories.Columns.Add("categoryName", typeof(string));
            categories.Columns.Add("description", typeof(string));
            
            categories.Rows.Add(1, "Gold Coins", "Precious gold coins");
            categories.Rows.Add(2, "Silver Coins", "Silver collectible coins");
            categories.Rows.Add(3, "Platinum Coins", "Rare platinum coins");
            
            // Tabla de productos
            DataTable products = new DataTable(PRODUCTS_TABLE);
            products.Columns.Add("productCode", typeof(string));
            products.Columns.Add("productName", typeof(string));
            products.Columns.Add("catNumber", typeof(int));
            products.Columns.Add("buyPrice", typeof(decimal));
            products.Columns.Add("MSRP", typeof(decimal));
            
            products.Rows.Add("COIN001", "American Gold Eagle", 1, 1800.00, 2000.00);
            products.Rows.Add("COIN002", "Canadian Maple Leaf", 2, 25.00, 30.00);
            products.Rows.Add("COIN003", "Austrian Philharmonic", 1, 1750.00, 1950.00);
            products.Rows.Add("COIN004", "Chinese Panda", 2, 35.00, 45.00);
            products.Rows.Add("COIN005", "Platinum Eagle", 3, 1200.00, 1400.00);
            
            // Filtrar por categoría si se especifica
            if (catNumber > 0)
            {
                DataTable filteredCategories = categories.Clone();
                DataTable filteredProducts = products.Clone();
                
                foreach (DataRow row in categories.Rows)
                {
                    if ((int)row["catNumber"] == catNumber)
                        filteredCategories.ImportRow(row);
                }
                
                foreach (DataRow row in products.Rows)
                {
                    if ((int)row["catNumber"] == catNumber)
                        filteredProducts.ImportRow(row);
                }
                
                ds.Tables.Add(filteredCategories);
                ds.Tables.Add(filteredProducts);
            }
            else
            {
                ds.Tables.Add(categories);
                ds.Tables.Add(products);
            }
            
            // Crear relación
            DataRelation dr = new DataRelation("cat_prods",
                ds.Tables[CATEGORIES_TABLE].Columns["catNumber"],
                ds.Tables[PRODUCTS_TABLE].Columns["catNumber"],
                false);
            ds.Relations.Add(dr);
            
            return ds;
        }

        public DataSet GetEmailByName(string name)
        {
            DataSet ds = new DataSet();
            DataTable dt = new DataTable();
            dt.Columns.Add("name", typeof(string));
            dt.Columns.Add(EMAIL_COLUMN, typeof(string));
            
            // Simular búsqueda por nombre - mantener vulnerabilidad
            dt.Rows.Add("Admin User", ADMIN_EMAIL);
            dt.Rows.Add("Test User", TEST_EMAIL);
            dt.Rows.Add(name, name.ToLower().Replace(" ", "") + "@webgoat.com");
            
            ds.Tables.Add(dt);
            return ds;
        }

        public string GetEmailByCustomerNumber(string num)
        {
            var emails = new Dictionary<string, string>
            {
                {"1", ADMIN_EMAIL},
                {"2", USER_EMAIL},
                {"3", TEST_EMAIL}
            };
            
            return emails.ContainsKey(num) ? emails[num] : "customer" + num + "@webgoat.com";
        }

        public DataSet GetCustomerEmails(string email)
        {
            DataSet ds = new DataSet();
            DataTable dt = new DataTable();
            dt.Columns.Add("customerNumber", typeof(int));
            dt.Columns.Add(EMAIL_COLUMN, typeof(string));
            dt.Columns.Add("customerName", typeof(string));
            
            // Simular búsqueda de emails - mantener posibles vulnerabilidades
            dt.Rows.Add(1, ADMIN_EMAIL, "Admin User");
            dt.Rows.Add(2, USER_EMAIL, "Regular User");
            dt.Rows.Add(3, TEST_EMAIL, "Test User");
            
            if (!string.IsNullOrEmpty(email))
            {
                dt.Rows.Add(999, email, "Search Result for: " + email);
            }
            
            ds.Tables.Add(dt);
            return ds;
        }

        public string Name
        {
            get { return "MockedData"; }
        }
    }
}

