---
title: Site Revamp
date: 2025-09-14
extra:
  started_writing: 2025-08-30
---

So, one afternoon, a couple of months ago, I got bored and ended up browsing the dark web.
Against my expectations I quickly found myself back on the clear web on an obscure blog whose .onion address had been linked to on a link list.
Reading around the blog proved fascinating, not necessarily for the content of it (eventhough there was some interesting stuff there, see [artemislena.eu](https://artemislena.eu/)), but more so for something it linked to: <u>A webring</u>.

For those that don't know (I didn't): A [webring](https://wikipedia.org/wiki/webring) basically consists of a bunch of websites that link to each other in a circle, usually with some kind of common theme and a common navigation bar.
What fascinated me about this was that this was a relic of the old internet which I had believed to have died when social media came around.
Yet here it was, alive and well, just hidden from view waiting for one to find a website from which to start *surfing*.

After proceeding to spend the entire evening reading around various blogs, I kind of forgot about it for a while due to a lack of spare time.
Then, a couple of days before starting to write this, I remembered that afternoon and fell down the rabbit hole *again*.
Several hours later, having already been unhappy with the uninspired, bland state my website was in at this point, I decided I would completely revamp it.

For this I had a couple of things in mind that I noticed while surfing which I wanted to adopt for my website.
First of I wanted to keep any and all javascript off of my site.
This is because I don't have any ambitions for this place beyond publishing my writeups and writing the occasional blog post and such things should not require javascript.
Additionally this should hopefully make the website work properly in terminal based browsers.

Another thing I came across is Jeff Huang's post ["This Page is Designed to Last"](https://jeffhuang.com/designed_to_last/).
It advocates for building web sites in ways that prevent them from requiring active maintenance to keep up since this maintenance typically dries up before the hosting does.
As someone who also really likes the [Stop Killing Games](https://www.stopkillinggames.com/) Movement, this immediately resonated with me since it also makes archival easier.
As a part of this I also switched from Jekyll, a Static Site Generator (SSG), which I was using previously to Zola, another SSG, because it is much simpler and faster and should thus simplify maintenance.
I also switched to using a system font stack in order to speed up page loads and avoid hotlinking to external font providers like Google (also [cuz fuck em that's why](https://www.youtube.com/watch?v=W_rGq5K_i3Q)).
In the same vein I try to avoid increasing the (compressed) size of the entire site too much to make load times faster and archival easier (also I want the 250KB club badge).

Lastly, since I like getting flash banged at 01:00 o'clock as little as the next guy/girl I want my page to have a proper dark mode and light mode without people needing to use dark reader.
