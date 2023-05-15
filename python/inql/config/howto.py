# coding: utf-8

howto = """
# 1. Welcome and Introduction

Hey there, welcome to InQL v5.0! We've been working hard to bring you this major
update, and we're excited to see you here. But, like a newly painted room, it
might still smell a bit of wet paint. In other words, as we've pretty much
rewritten this version from scratch, there could be new bugs lurking around. But
hey, that's what makes it fun, right? Let's dive in!

# 2. Getting Started

First off, let's make sure you've got the GQLSpection library plugged in. It's
our shiny new GraphQL parsing and formatting library that works with Python 2,
Python 3, and Jython. It also works as a CLI tool, so if you want to use some of
the InQL features in your scripts, check it out here:
https://github.com/doyensec/gqlspection.

Now, onto the main event: the InQL UI. You'll notice a new tab - 'InQL'. This
tab houses the heart of our new functionality, divided into two main subtabs:
'Scanner' and 'Attacker'.

## 2.1. Scanner: The Heart of InQL v5.0

The Scanner is where the magic happens. Here, you provide the GraphQL endpoint
URL and optionally, a local file holding the introspection schema in JSON
format. If you don't provide a file, don't worry! InQL will politely ask the
server for it. If you do have a schema file, the scanner will work offline - no
network requests sent. After hitting the 'Analyze' button, InQL will generate
all possible queries and mutations, and display them in a neatly organized
fileview.

### 2.1.1. Customizing Your Scan

InQL v5.0 isn't just about what we can do - it's about what you can do. You can
customize the depth of the generated queries (by default, we limit it to two
levels, but feel free to change that in the Settings menu). Want to change the
number of spaces used for indentation? You can do that too. You can even dump
the introspection schema and run a 'Points of Interest' scan. This scan looks
for potential vulnerabilities in your GraphQL schema, things like authentication
issues, privileged access, personal data, and more. You can also provide custom
keywords for the points of interest scan.

### 2.1.2. Analyzing the Points of Interest

Once you've run your Points of Interest scan, you'll have a rich set of data to
explore. These points cover a wide range of categories that could be of interest
to pentesters and bug bounty hunters. You can enable or disable these categories
in the Settings, and generate reports in plain text or JSON formats.

### 2.1.3. Enhanced Interactions with Burp

We've made it super easy for you to generate queries directly from a GraphQL
request in any Burp tool. Just right-click, select "Extensions" -> "InQL v5.0"
-> "Generate queries with InQL Scanner", and voila! You can also send
auto-generated queries to other Burp tools for further analysis.

### 2.1.4. Setting Custom Headers

InQL v5.0 allows you to set custom headers. This can be done via the "Custom
Headers" button, located to the left of the "Analyze" button. Currently, headers
are set per domain, with the list of domains auto-populated from observed
traffic. You can also add new ones using the 'Add Domain' button.

## 2.2. Attacker: The Batch Attack Tool

In the Attacker tab, you can run batch GraphQL attacks. Modify the GraphQL
request to include a placeholder, hit 'Send', and let the Attacker do its work.
Batch attacks can be particularly useful to bypass poorly-implemented rate
limits.

## 2.3. Enhancements to Burp's Native Message Editors

We've also added a little spice to your favorite Burp tools. Now, any GraphQL
request in Burp's native message editors will have an extra tab labeled
'GraphQL'. This little tab is your new best friend for quickly viewing and
modifying GraphQL requests. No need to juggle between different tools,
everything is neatly integrated for your convenience.

# 3. Features Deprecated and Coming Soon

We realize change can be tough. In our journey to make InQL v5.0 better, we had
to say goodbye to a few features from InQL v4. The standalone and CLI modes have
been retired, with the CLI functionality now living in the GQLSpection library.
And for now, we've also had to part ways with our embedded GraphiQL server,
which we know was a favorite for many.

You might also notice that the 'Timer' tab from InQL v4 is missing in action.
This feature used to help identify slow requests, potentially unearthing DoS
vulnerabilities. But fear not! We removed the 'Timer' because Burp's built-in
'Logger' tool does the job even better.

For those of you fond of the 'Timer', we recommend using 'Logger'. Pay special
attention to the 'Start response timer' and 'Stop response timer' columns. The
'Stop response timer' holds the data that 'Timer' used to display. Although, the
data in 'Logger' is more precise, which we can't match due to limitations in
Burp's API exposure.

Interestingly, the 'Start response timer' is a better indicator of response
times, but again, it's not accessible through the API. The difference between
the 'Start' and 'Stop' timers gives you the response time from the server.

So, while we bid adieu to the 'Timer', we encourage you to embrace the 'Logger'.
It's a change for the better, we promise!

However, it's not all sad news. While we couldn't bring everything over to v5.0,
we're already hard at work on v5.1. We're planning to bring back the cycle/loop
detection and, yes, the much-loved GraphiQL server. So, stay tuned!

# 4. Join the Team!

Open source projects like InQL thrive on community contributions, and we're
always on the lookout for fresh talent to join our team. Whether you're a
developer, designer, researcher, or just someone with a knack for finding bugs,
there's a place for you here.

Don't be shy! File bugs, give us feedback, and if you're feeling bold, submit a
pull request. Every contribution, big or small, helps us make InQL better. So,
dive in, get your hands dirty, and help shape the future of GraphQL testing.

Remember, the best way to interact with us is through the Github issue tracker.
But you can also reach us on social media (@Doyensec, @execveat). We're excited
to hear from you!

# 5. Conclusion

And that's the grand tour of InQL v5.0! We hope you find these new features and
improvements as exciting as we do. We've worked hard to make your GraphQL
testing more efficient and effective, and we can't wait to see what you'll do
with it.

As we wrap up, remember that InQL, like all tools, is just that - a tool. It's a
powerful one, sure, but its true power comes from you, the pentester. So get out
there, start testing, and uncover those vulnerabilities!

Thanks for choosing InQL. Happy testing!

Your InQL team.
"""
