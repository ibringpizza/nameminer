# nameminer
nameminer allows you to generate a list of available domains (.com/.net) from combined word lists and sort/analyze them in a variety of ways.

The Jackson JSON ObjectMapper and Apache Commons Net 3.6 libraries are needed to run nameminer.

Functionality:

combine LIST LIST - prefix lists + suffix lists (seperated by commas)

load PATH - load, reload, set current list

s LIST KEYWORD - append keywords to words in lists (seperated by commas)

reload - rereads all lists in default list folder ("./name miner lists")

check FILEPATH - checks domains in file and prints available with appraisal

checkregdates FILEPATH/DOMAIN - returns registration dates of domains in file

pscore/sscore - loads currently used prefixes/suffixes with number of available names in most recent (current) search

ssort - returns loaded scores sorted - high demand words are printed last

preview LIST - prints first 5 entries in a list

settld TLD - sets tld

lists - displays all lists that are loaded

sort - sorts current list of domains by appraisal

sortr - sort regged tlds

getregged - prints names registered in at least 1 tld

sortlength - sorts current list by length

save NAME - saves current list state to a txt file in your Downloads

togglea - toggles appraisals, will print names that are available without appraisal (faster). does not save names automatically

toggler - toggles regged tlds

help - print the help menu

Important notes:

On launch, all files are loaded from a folder called "name miner lists" in the current working directory

The listFromName method checks for the first list name that contains the substring you provide. You can use unique shortnames to refer to your lists. A common shortname will select the first matching file name in the directory.

Any command that iterates through a new set of domains overrides the previous list of domains. You can only sort/save/etc. the current list.

#### Examples
![image](https://user-images.githubusercontent.com/52234395/216752372-2abd4a92-17bf-4726-9c96-a6f3523ad54a.png)

![image](https://user-images.githubusercontent.com/52234395/216752383-81fb9de6-c41d-4ec1-919d-b22405ee29e2.png)

![image](https://user-images.githubusercontent.com/52234395/216752389-78117ef3-3b32-42c7-871c-b35afe2d8e7c.png)

![image](https://user-images.githubusercontent.com/52234395/216752405-7dbd95a1-a3af-44b6-9784-9175f9a35e79.png)

![image](https://user-images.githubusercontent.com/52234395/216752427-bd1f1009-a699-40fa-a733-515523c535df.png)


Needs fixing:

- May not handle folders in default list location
