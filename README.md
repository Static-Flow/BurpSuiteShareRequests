# BurpSuiteShareRequests
This Burp Suite extension enables the generation of shareable links to specific requests which other Burp Suite users can import. If this collaboration feature is useful, checkout my main extension https://github.com/Static-Flow/BurpSuite-Team-Extension which includes this functionality and more!

# How To Use
Once this extension is installed a new tab titled "Burp Share Requests" will appear in Burp Suite which will contain all the currently generated links that are ready to be shared.

To create these links right click on a Request from either the Site Map, HTTP History, Intercept Tab, or Repeater tab and select the "create link" option within the context menu options. This will generate a new line within the "Burp Share Requests" showing the URL of the Request you generated a link for. 

To share the Request with others, right click on the desired request within the "Burp Share Requests" tab and select "Get link" to generate a link suitable for pasting into a browser URL bar (i.e. http://burpsharedrequest/...) or select "Get HTML Link" to generate a link suitable for including in a report or blog post (i.e. <a href='http://burpsharedrequest/...'>http://burpsharedrequest/</a>
