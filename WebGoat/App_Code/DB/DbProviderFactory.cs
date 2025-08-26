using System;
using System.Collections.Generic;
using System.Diagnostics;
using log4net;
using System.Reflection;

namespace OWASP.WebGoat.NET.App_Code.DB
{
    //NOT THREAD SAFE!
    public static class DbProviderFactory
    {
        private static ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        
        public static IDbProvider Create(ConfigFile configFile)
        {
            // Para el hackathon, usar siempre el proveedor mockeado
            log.Info("Creating mocked data provider for hackathon");
            return new DummyDbProvider();
        }
    }
}