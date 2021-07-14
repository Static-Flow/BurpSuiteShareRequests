# BurpSuiteShareRequests
This Burp Suite extension enables the generation of shareable links to specific requests which other Burp Suite users can import. Requests are shared using a intermediary API which stores the request as an AES encrypted blob which can only be decrypted using a user unique key which is never sent or stored server side. 

# How To Use
Once this extension is installed a new tab titled "Burp Share Requests" will appear in Burp Suite which will contain all the currently generated links that are ready to be shared.

An account is required to generate shareable links but not to import them. When the extension loads a signup for is presented. If you already have an account a link below will take you to the signin page.

Once you have signed in, you can create shareable links by right clicking on a Request from either the Site Map, HTTP History, Intercept Tab, or Repeater tab and select the "create link" option within the context menu options. This will generate a new line within the "Burp Share Requests" showing the shareable URL to the request  and the URL of the request you generated a link for. 

To share the Request with others, right click on the desired request within the "Burp Share Requests" tab and select "Get link" to generate a link suitable for pasting into a browser URL bar (i.e. http://burpsharedrequest/...).
