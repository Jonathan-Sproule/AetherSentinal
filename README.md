🧠 What even is this?
Okay, so you know how you have a network, and you're like, "Wow, what are all these devices and why is one of them named ‘ESP8266_POTATO_BOT_2’?" Yeah, same.
NetMemo is that gremlin you install on your machine that just starts watching. It scans your network, pokes at stuff, writes everything down like it's gonna tattle, and then gets real stressed out if something changes.

It’s like the overachiever version of nmap that drank too much Red Bull and started keeping a diary.

🛠️ What does it actually do?
Scans your network? ✅

Logs what it finds? ✅

Keeps it all in a MySQL brain-dump? ✅

Notices when your printer suddenly gets a new IP and asks “Who dis?” ✅

Draws pretty diagrams (eventually)? 🖼️ Working on it, don't @ me

Has a flag to scream about open ports and sketchy services? ✅ -ps = "please scan" or "port stress", your call

Knows about WiFi networks? Oh you betcha. It’ll sniff those too.

CLI only? Hell yeah. No GUIs here. Real devs fear mice.

🧠 Memory tracking? Diff engine? What?
Yeah. So imagine this:

You scan today, and it sees a bunch of familiar devices.

You scan next week, and now there’s a new guy.

NetMemo’s like: “Uhh... that’s not Todd. Who the hell is that?”

It keeps a record of every scan, and when things change, it raises a little digital eyebrow. One day, it might even learn to say: "Hey, that IP never had port 22 open before. Should we be worried?"

It’s basically training wheels for building your own IDS, with a side of "forensic hoarder."

🧙 WiFi Wizardry
NetMemo doesn’t just watch your Ethernet party — it’s also lurking in the wireless shadows.

Sniffs SSIDs

Grabs BSSIDs (those MACs, baby)

Checks signal strength and encryption

Probably wonders why there are 14 open hotspots named “xX_DARKNET_Xx”

Just feed it the --wifi flag and let the radio waves flow.

🧰 Modularity (a.k.a. organized chaos)
The code is split up so future you can come back and not scream (as much):

cli.py – yells at the user when they forget flags

scan_engine.py – does the actual poking and sniffing

db.py – dumps things into MySQL like a responsible adult

differ.py – the part that says “Yo, something’s different”

visualizer.py – eventually makes network art (just needs crayons)

🧪 What’s the Point?
Honestly? Learning.

Also? To stop being bad at network mapping.

Also also? To make a tool that watches your network and throws a fit when something’s weird — which is exactly the kind of petty behavior we respect in our tools.


*THIS IS AI GENERATED CONTENT IN THE STYLING OF MICHEAL REEVES*
