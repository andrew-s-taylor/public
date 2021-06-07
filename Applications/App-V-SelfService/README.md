An App-V Self-Service tool to enable users to add/remove themselves from application access

Use this if using full infrastructure mode

Requires delegated AD service account with access to OU containing App-V AD groups and a database account with read-only access to the App-V database (both configured in the .config file)

Edit these params:
<configuration>
  <appSettings>
    <add key="Domain" value=""/>
    <add key="DefaultOU" value=""/>
    <add key="DefaultRootOU" value="DC=yourou"/>
    <add key="ServiceUser" value=""/>
    <add key="ServicePassword" value=""/>
    <add key="ADGroup" value=""/>
    <add key="ClientSettingsProvider.ServiceUri" value=""/>
  </appSettings>
  <connectionStrings>
    <add name="AppDatabase" connectionString="Data Source=SERVER;Database=AppVManagement;User id=id;Password=password"/>
  </connectionStrings>
