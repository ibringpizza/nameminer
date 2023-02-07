package nameminer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import org.apache.commons.net.whois.WhoisClient;
import org.codehaus.jackson.map.ObjectMapper;

public class NameMiner {
    
    static Map<String, List<String>> map = new HashMap<>();
    static String tld = ".com";
    static LinkedHashMap<String, Integer[]> currentList = new LinkedHashMap<>();
    static LinkedHashMap<String, Integer> currentScoreList = new LinkedHashMap<>();
    static List<String> currentPrefixes = new ArrayList<>();
    static List<String> currentSuffixes = new ArrayList<>();
    static List<String> available_domains = new ArrayList<>();
    static Comparable_Sales[] relatedSales = new Comparable_Sales[0];
    static BufferedWriter writeAll;
    static boolean appraiseToggle = true;
    static boolean regToggle = true;
    
    static Comparator<Entry<String, Integer>> compare = (Entry<String, Integer> a1, Entry<String, Integer> a2) -> {
        Integer ap1 = a1.getValue();
        Integer ap2 = a2.getValue();
        return ap2.compareTo(ap1);
    };
    
    static Comparator<Entry<String, Integer[]>> compareLength = (Entry<String, Integer[]> a1, Entry<String, Integer[]> a2) -> {
        Integer ap1 = a1.getKey().length();
        Integer ap2 = a2.getKey().length();
        return ap1.compareTo(ap2);
    };

    public static void main(String[] args) {
        //only supports .com, .net, .gov
        try {
            writeAll = new BufferedWriter(new FileWriter("nameminer_all.txt", true));
        } catch (IOException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("load list and enter prefix" + "\n")
            .append("combine LIST LIST - prefix lists + suffix lists (seperated by commas)" + "\n")
            .append("load PATH - load, reload, set current list" + "\n")
            .append("s LIST KEYWORD - append keywords to words in lists (seperated by commas)" + "\n")
            .append("reload - reload lists in main directory" + "\n")
            .append("check PATH/DOMAIN - checks domains in file and prints available with appraisal" + "\n")
            .append("checkregdates PATH/DOMAIN - checks registration date of registered domains in file" + "\n")
            .append("pscore/sscore - loads currently used prefixes/suffixes with number of available names in most recent (current) search" + "\n")
            .append("ssort - returns loaded scores sorted - high demand words are printed last" + "\n")
            .append("preview LIST - prints first 5 entries in a list" + "\n")
            .append("settld TLD" + "\n")
            .append("lists - lists loaded" + "\n")
            .append("sort" + "\n")
            .append("sortr - sort regged tlds" + "\n")
            .append("getregged - prints names registered in at least 1 tld" + "\n")
            .append("sortlength" + "\n")
            .append("save NAME" + "\n")
            .append("togglea - toggles appraisals, will print names that are available without appraisal (faster). does not save names automatically" + "\n")
            .append("toggler - toggles regged tlds" + "\n")
            .append("help");
        
        System.out.println(sb.toString());
        
        String prefix = "";
        String currentListName = "";
        
        reload();
        while(true){
            Scanner input = new Scanner(System.in);
            String cmd = input.nextLine();
            cmd = cmd.replaceAll("\"", "");
            String[] command = cmd.split(" ");
            if(command[0].equals("load")){
                currentSuffixes.clear();
                String paths = command[1];
                for(String path : paths.split(",")){
                    if(listFromName(path) == null)loadList(path);
                    listFromName(path).stream().forEach(word -> currentSuffixes.add(word));
                    currentListName = command[1];
                }
                System.out.println("loaded");
            }else if(cmd.equals("reload")){
                reload();
                System.out.println("reloaded");
            }else if(command[0].equals("check")){
                long start = System.currentTimeMillis();
                String in = command[1];
                if(in.matches("[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}"))
                    System.out.println(in + (Avail.checkAvail(in) ? " is available" : " is not available"));
                else{
                    try {
                        available_domains.clear();
                        File file = new File(command[1]);
                        List<String> list = Files.readAllLines(file.toPath());
			List<String> toCheck = new ArrayList<>();
                        list.stream().filter(domain -> domain.matches("[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}")).forEach(domain -> toCheck.add(domain));

                        int frags = ((toCheck.size()/100) > 1 ? Math.round(toCheck.size()/100) : 1);
                        List<List<String>> fragged = frag(toCheck, (frags > 16 ? 16 : frags));
                        Thread[] ta = new Thread[fragged.size()];
                        for(int i = 0;i<fragged.size();i++){
                            Avail a = new Avail(fragged.get(i), false);
                            a.start();
                            ta[i] = a;
                        }
                        try{
                            for(int i = 0;i<ta.length;i++)
                                ta[i].join();
                        } catch (InterruptedException ex) {
                                Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        available_domains.stream().forEach(System.out::println);
                    } catch (IOException ex) {
                        Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    calcTime(start, "finished checking availability");
                }  
            }else if(command[0].equals("checkregdates")){
                if(command[1].matches("[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}")){
                    getRegDate(command[1]);
                }else{
                    try {
                        available_domains.clear();
                        File file = new File(command[1]);
                        List<String> list = Files.readAllLines(file.toPath());
			List<String> toCheck = new ArrayList<>();
                        list.stream().filter(domain -> domain.matches("[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}")).forEach(domain -> toCheck.add(domain));

                        int frags = ((toCheck.size()/100) > 1 ? Math.round(toCheck.size()/100) : 1);
                        List<List<String>> fragged = frag(toCheck, (frags > 16 ? 16 : frags));
                        Thread[] ta = new Thread[fragged.size()];
                        for(int i = 0;i<fragged.size();i++){
                            Avail a = new Avail(fragged.get(i), true);
                            a.start();
                            ta[i] = a;
                        }
                        try{
                            for(int i = 0;i<ta.length;i++)
                                ta[i].join();
                        } catch (InterruptedException ex) {
                                Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        available_domains.stream().forEach(System.out::println);
                        System.out.println("finished");
                    } catch (IOException ex) {
                        Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }else if(cmd.length() >= 6 && cmd.substring(1,6).equals("score")){
                currentScoreList.clear();
                if(cmd.startsWith("p")){
                    for(String p : currentPrefixes){
                        int matched = 0;
                        for(String domain : currentList.keySet())
                            if(domain.startsWith(p))matched++;
                        //System.out.println(p + " - " + matched);
                        currentScoreList.put(p, matched);
                    }
                }else if(cmd.startsWith("s")){
                    for(String s : currentSuffixes){
                        int matched = 0;
                        for(String domain : currentList.keySet())
                            if(domain.endsWith(s + tld))matched++;
                        //System.out.println(s + " - " + matched);
                        currentScoreList.put(s, matched);
                    }
                }
            }else if(command[0].equals("regged")){
                if(command[1].matches("[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}"))
                    System.out.println(tldsregged(command[1]));
                else
                    System.out.println("invalid domain");
            }else if(cmd.equals("ssort")){
                Set values = currentScoreList.entrySet();
                List<Entry<String, Integer>> list = new ArrayList<>(values);
                Collections.sort(list, compare);
                currentScoreList.clear();
                for (Entry<String, Integer> entry : list) {
                    System.out.println(entry.getKey() + " - " + entry.getValue());
                    currentScoreList.put(entry.getKey(), entry.getValue());
                }
            }else if(command[0].equals("preview")){
                String name = command[1];
                List<String> list = listFromName(name);
                list.stream().limit(5).forEach(entry -> System.out.println(entry));
            }else if(command[0].equals("settld"))
                tld = command[1];
            else if(cmd.equals("lists"))
                map.keySet().stream().forEach(System.out::println);
            else if(command[0].equals("combine")){
                currentList.clear();
                currentPrefixes.clear();
                currentSuffixes.clear();
                long start = System.currentTimeMillis();
                for(String plist : command[1].split(",")){
                    for(String slist : command[2].split(",")){
                        listFromName(plist).stream().forEach(p -> currentPrefixes.add(p));
                        listFromName(slist).stream().forEach(s -> currentSuffixes.add(s));
                        combine(listFromName(plist), listFromName(slist));
                    }
                }
                long finish = System.currentTimeMillis();
                double seconds = (finish-start)/1000;
                int minutes = (int) Math.floor(seconds/60);
                System.out.println("finished ~" + (minutes > 0 ? minutes + " minutes " : "") + seconds%60 + " seconds");
            }else if(cmd.equals("sort")){
                Set values = currentList.entrySet();
                List<Entry<String, Integer[]>> list = new ArrayList<>(values);
                list.sort((a1, a2) -> a2.getValue()[0].compareTo(a1.getValue()[0]));
                currentList.clear();
                for(Entry<String, Integer[]> entry : list){
                    System.out.println(entry.getKey() + " -> " + entry.getValue()[0] + ", " + entry.getValue()[1]);
                    currentList.put(entry.getKey(), entry.getValue());
                }
            }else if(cmd.equals("sortr")){
                Set values = currentList.entrySet();
                List<Entry<String, Integer[]>> list = new ArrayList<>(values);
                list.sort((a1, a2) -> a2.getValue()[1].compareTo(a1.getValue()[1]));
                currentList.clear();
                for(Entry<String, Integer[]> entry : list){
                    System.out.println(entry.getKey() + " -> " + entry.getValue()[0] + ", " + entry.getValue()[1]);
                    currentList.put(entry.getKey(), entry.getValue());
                }
            }else if(cmd.equals("getregged")){
                Set values = currentList.entrySet();
                List<Entry<String, Integer[]>> list = new ArrayList<>(values);
                list.sort((a1, a2) -> a2.getValue()[1].compareTo(a1.getValue()[1]));
                currentList.clear();
                for(Entry<String, Integer[]> entry : list){
                    if(entry.getValue()[1] > 0)System.out.println(entry.getKey() + " -> " + entry.getValue()[0] + ", " + entry.getValue()[1]);
                    currentList.put(entry.getKey(), entry.getValue());
                }
            }else if(command[0].equals("s")){
                currentList.clear();
                currentPrefixes.clear();
                currentSuffixes.clear();
                long start = System.currentTimeMillis();
                for(String sword : command[2].split(",")){
                    for(String plist : command[1].split(",")){
                        listFromName(plist).stream().forEach(p -> currentPrefixes.add(p));
                        combine(listFromName(plist), sword);
                    }
                    currentSuffixes.add(sword);
                }
                long finish = System.currentTimeMillis();
                double seconds = (finish-start)/1000;
                int minutes = (int) Math.floor(seconds/60);
                System.out.println("finished ~" + (minutes > 0 ? minutes + " minutes " : "") + seconds%60 + " seconds");
            }else if(cmd.equals("sortlength")){
                Set values = currentList.entrySet();
                List<Entry<String, Integer[]>> list = new ArrayList<>(values);
                Collections.sort(list, compareLength);
                currentList.clear();
                for (Entry<String, Integer[]> entry : list) {
                    System.out.println(entry.getKey() + " -> " + entry.getValue());
                    currentList.put(entry.getKey(), entry.getValue());
                }
            }else if(cmd.matches("save [a-zA-Z0-9]+")){
                File file = new File(cmd.substring(5, cmd.length()) + ".txt");
                try {
                    final BufferedWriter bw = new BufferedWriter(new FileWriter(file));
                    currentList.entrySet().stream().forEach(entry -> {
                        try {
                            bw.write(entry.getKey() + "," + entry.getValue() + "\n");
                        } catch (IOException ex) { }
                    });
                    bw.flush();
                    bw.close();
                    System.out.println("current map state saved");
                } catch (IOException ex) { }
            
            }else if(cmd.equals("togglea")){
                appraiseToggle = !appraiseToggle;
                System.out.println("appraisals toggled " + (appraiseToggle ? "off" : "on"));
            }else if(cmd.equals("toggler")){
                regToggle = !regToggle;
                System.out.println("regged tlds toggled " + (regToggle ? "off" : "on"));
            }else if(cmd.equals("help"))
                System.out.println(sb.toString());
            else if(cmd.equals("")){
                continue;
            }else{
                currentList.clear();
                currentPrefixes.clear();
                long start = System.currentTimeMillis();
                for(String p : cmd.split(",")){
                    prefix = p;
                    currentPrefixes.add(p);
                    combine(prefix, currentSuffixes);
                }
                long finish = System.currentTimeMillis();
                double seconds = (finish-start)/1000;
                int minutes = (int) Math.floor(seconds/60);
                System.out.println("finished ~" + (minutes > 0 ? minutes + " minutes " : "") + seconds%60 + " seconds");
            }
        }
    }
    
    static void check(String path){
        try {
            File file = new File(path);
            List<String> list = Files.readAllLines(file.toPath());
            list.stream().filter(domain -> domain.matches("[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}") && Avail.checkAvail(domain)).forEach(domain -> {
                if(appraiseToggle){
                    int tldsreg = tldsregged(domain);
                    System.out.println(domain + (!regToggle ? " -> " + tldsreg : ""));
                }else
                    try {
                        int appraisal = appraise(domain);
                        int tldsreg = tldsregged(domain);
                        String info = domain + " -> " + appraisal + (!regToggle ? ", " + tldsreg : "");
                        System.out.println(info);
                        writeAll.append(info + "\n");
                    } catch (IOException ex) {
                        Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
                    }
            });
            writeAll.flush();
        } catch (IOException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    static void reload(){
        File directory = new File("name miner lists");
        for (File file : directory.listFiles()) {
            try {
                map.put(file.getPath(), Files.readAllLines(file.toPath()));
            } catch(AccessDeniedException ex){ //directory in list directory
                
            }catch (IOException ex) {
                //Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    static List<String> listFromName(String name){
        try{
            return map.entrySet().stream().filter(entry -> entry.getKey().toLowerCase().contains(name)).findAny().get().getValue();
        }catch(Exception e){
            System.out.println("No list named \'" + name + "\'");
        }
        return new ArrayList<>();
    }
    
    static void combine(List<String> prefixes, List<String> suffixes){
        //currentList.clear();
        available_domains.clear();
        List<String> toCheck = new ArrayList<>();
        for(String prefix : prefixes){
            for(String suffix : suffixes){
                String domain = prefix + suffix + tld;
                if(domain.matches("[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}"))
                    toCheck.add(domain);
            }
        }
        int frags = ((toCheck.size()/100) > 1 ? Math.round(toCheck.size()/100) : 1);
        List<List<String>> fragged = frag(toCheck, (frags > 16 ? 16 : frags));
        Thread[] ta = new Thread[fragged.size()];
        for(int i = 0;i<fragged.size();i++){
            Avail a = new Avail(fragged.get(i), false);
            a.start();
            ta[i] = a;
        }
        try{
            for(int i = 0;i<ta.length;i++)
                ta[i].join();
        } catch (InterruptedException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        }
        for(String domain : available_domains){
            if(appraiseToggle){
                int tldsreg = tldsregged(domain);
                System.out.println(domain + (!regToggle ? " -> " + tldsreg : ""));
                currentList.put(domain, new Integer[]{0, tldsreg});
            }else
                try {
                    int appraisal = appraise(domain);
                    int tldsreg = tldsregged(domain);
                    String info = domain + " -> " + appraisal + (!regToggle ? ", " + tldsreg : "");
                    System.out.println(info);
                    writeAll.append(info + "\n");
                    currentList.put(domain, new Integer[]{appraisal, tldsreg});
                } catch (IOException ex) {
                    Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
                }
        }
        try {
            writeAll.flush();
        } catch (IOException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    static void combine(String prefix, List<String> suffixes){
        //currentList.clear();
        available_domains.clear();
        List<String> toCheck = new ArrayList<>();
        for(String suffix : suffixes){
            String domain = prefix + suffix + tld;
            if(domain.matches("[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}"))
                toCheck.add(domain);
        }
        int frags = ((toCheck.size()/100) > 1 ? Math.round(toCheck.size()/100) : 1);
        List<List<String>> fragged = frag(toCheck, (frags > 16 ? 16 : frags));
        Thread[] ta = new Thread[fragged.size()];
        for(int i = 0;i<fragged.size();i++){
            Avail a = new Avail(fragged.get(i), false);
            a.start();
            ta[i] = a;
        }
        try{
            for(int i = 0;i<ta.length;i++)
                ta[i].join();
        } catch (InterruptedException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        }
        for(String domain : available_domains){
            if(appraiseToggle){
                    int tldsreg = tldsregged(domain);
                    System.out.println(domain + (!regToggle ? " -> " + tldsreg : ""));
                    currentList.put(domain, new Integer[]{0, tldsreg});
            }else
                try {
                    int appraisal = appraise(domain);
                    int tldsreg = tldsregged(domain);
                    String info = domain + " -> " + appraisal + (!regToggle ? ", " + tldsreg : "");
                    System.out.println(info);
                    writeAll.append(info + "\n");
                    currentList.put(domain, new Integer[]{appraisal, tldsreg});
                } catch (IOException ex) {
                    Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
                }
        }
        try {
            writeAll.flush();
        } catch (IOException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    static void combine(List<String> prefixes, String suffix){
        //currentList.clear();
        available_domains.clear();
        List<String> toCheck = new ArrayList<>();
        for(String prefix : prefixes){
            String domain = prefix + suffix + tld;
            if(domain.matches("[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}"))
                toCheck.add(domain);
        }
        int frags = ((toCheck.size()/100) > 1 ? Math.round(toCheck.size()/100) : 1);
        List<List<String>> fragged = frag(toCheck, (frags > 16 ? 16 : frags));
        Thread[] ta = new Thread[fragged.size()];
        for(int i = 0;i<fragged.size();i++){
            Avail a = new Avail(fragged.get(i), false);
            a.start();
            ta[i] = a;
        }
        try{
            for(int i = 0;i<ta.length;i++)
                ta[i].join();
        } catch (InterruptedException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        }
        for(String domain : available_domains){
            if(appraiseToggle){
                    int tldsreg = tldsregged(domain);
                    System.out.println(domain + (!regToggle ? " -> " + tldsreg : ""));
                    currentList.put(domain, new Integer[]{0, tldsreg});
            }else
                try {
                    int appraisal = appraise(domain);
                    int tldsreg = tldsregged(domain);
                    String info = domain + " -> " + appraisal + (!regToggle ? ", " + tldsreg : "");
                    System.out.println(info);
                    writeAll.append(info + "\n");
                    currentList.put(domain, new Integer[]{appraisal, tldsreg});
                } catch (IOException ex) {
                    Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
                }
        }
        try {
            writeAll.flush();
        } catch (IOException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static List<List<String>> frag(List<String> list, int frags){
        List<List<String>> biglist = new ArrayList<>();
        int from = 0;
        for(int i = 0;i<frags-1;i++){
            biglist.add(list.subList(from, (int) (from+Math.floor(list.size()/frags))));
            from += Math.floor(list.size()/frags);
        }
        biglist.add(list.subList(from, list.size()-1));
        return biglist;
    }
    
    static void loadList(String path){
        File file = new File(path);
        BufferedReader br = null;
        List<String> list = new ArrayList<>();
        try {
            br = new BufferedReader(new FileReader(file));
            String line;
            while((line = br.readLine()) != null)list.add(line);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        }
        map.put(path, list);
    }
    /*
    static boolean Avail.checkAvail(String domain){
        String pattern = "No match for";
        Pattern p = Pattern.compile(pattern);
        boolean fin = false;
        while(!fin){
            try {
                WhoisClient whois;
                whois = new WhoisClient();
                String result = null;
                try{
                    whois.connect(WhoisClient.DEFAULT_HOST);
                    result = whois.query(domain);
                } catch(Exception ex){
                    waitForConnection();
                }
                Matcher match = p.matcher(result.substring(0, 12));
                whois.disconnect();
                fin = true;
                if(match.find())return true;
            } catch (IOException ex) {
                Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
            }catch(Exception ex){
                waitForConnection();
            }
        }
        return false;
    }
    */
    static void getRegDate(String domain){
        String pattern = "(Creation Date: )([A-Z0-9-:]+)";
        Pattern p = Pattern.compile(pattern);
        boolean fin = false;
        while (!fin) {
            try {
                WhoisClient whois;
                whois = new WhoisClient();
                String result = null;
                try {
                    whois.connect(WhoisClient.DEFAULT_HOST);
                    result = whois.query(domain);
                } catch (Exception ex) {
                    waitForConnection();
                }
                Matcher match = p.matcher(result);
                whois.disconnect();
                fin = true;
                if (match.find()) 
                    System.out.println(domain + ": " + match.group(2));
            } catch (IOException ex) {
                Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
            } catch (Exception ex) {
                waitForConnection();
            }
        }
    }
    
    public static int appraise(String domain) throws MalformedURLException, IOException {
        int appraisal = 0;
        int responseCode = 0;
        HttpsURLConnection connect = null;
        String link = "https://api.godaddy.com/v1/appraisal/" + domain;
        URL url = new URL(link);
        while (responseCode != 200) {
            try {
                connect = (HttpsURLConnection) url.openConnection();
                connect.setRequestMethod("GET");
                connect.addRequestProperty("accept", "application/json");
                responseCode = connect.getResponseCode();
                Thread.sleep(2000);
            } catch (UnknownHostException ex) {
                waitForConnection();
            } catch (Exception e) {
                waitForConnection();
            }
        }
        BufferedReader br = new BufferedReader(new InputStreamReader(connect.getInputStream()));
        ObjectMapper om = new ObjectMapper();
        MainParser mp = om.readValue(br.readLine(), MainParser.class);
        try{
            String path = "nameminer_godaddy.txt";
            File comparableOut = new File(path);
            BufferedWriter bw = new BufferedWriter(new FileWriter(comparableOut, true));
            relatedSales = mp.getComparable_sales();
            for(Comparable_Sales sale : relatedSales)
                bw.write(sale.toString() + "\n");
            bw.flush();
        }catch(Exception e){
            
        }
        return Integer.parseInt(mp.getGovalue());
    }
    
    public static int tldsregged(String domain) {
        if(regToggle)return -1;
        domain = domain.toLowerCase();
        int regged = -1;
        int responseCode = 0;
        HttpsURLConnection connect = null;
        String link = "https://dotdb.com/search?keyword=" + domain.substring(0, domain.indexOf(".")) + "&position=any&exclude=";
        URL url = null;
        try {
            url = new URL(link);
        } catch (MalformedURLException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
        }
        while (responseCode != 200) {
            try {
                connect = (HttpsURLConnection) url.openConnection();
                connect.setRequestMethod("GET");
                connect.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");
                responseCode = connect.getResponseCode();
                //System.out.println(responseCode);
//                DataInputStream is = new DataInputStream(connect.getInputStream());
//                byte[] bytes = new byte[is.readInt()];
//                is.readFully(bytes);
//                String line;
//                while((line = is.readLine()) != null){
//                    System.out.println(line);
//                }
                Thread.sleep(1000);
            } catch (UnknownHostException ex) {
                waitForConnection();
            } catch (Exception e) {
                waitForConnection();
            }
        }
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(connect.getInputStream()));
            String line;
            Pattern a = Pattern.compile("<td><strong>" + domain.substring(0, domain.indexOf(".")) + "</strong></td>"); //confirm that it is just domain
            Pattern p = Pattern.compile("(<td>)([0-9]+)(</td>)");
            while((line = br.readLine()) != null){
                Matcher ma = a.matcher(line);
                if(ma.find()){
                    String nextLine = br.readLine();
                    Matcher m = p.matcher(nextLine);
                    if(m.find())
                        regged = Integer.parseInt(m.group(2));
                    else
                        regged = 0;
                    break;
                }else{
                    regged = 0;
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
            regged = -1;
        }
        return regged;
    }

    public static boolean connected() {
        boolean connected = false;
        try {
            InetAddress addr = InetAddress.getByName("www.google.com");
            connected = addr.isReachable(2000);
        } catch (IOException ex) {
            connected = false;
        }
        return connected;
    }
    
    static void waitForConnection(){
        boolean checkConnection = connected();
        while (!checkConnection) {
            System.out.println("Checking connection...");
            checkConnection = connected();
            try {
                Thread.sleep(25000);
            } catch (InterruptedException ex) {
                Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        System.out.println("connected");
    }
    
    static void calcTime(long start, String msg){
        long finish = System.currentTimeMillis();
        double seconds = (finish-start)/1000;
        int minutes = (int) Math.floor(seconds/60);
        System.out.println(msg + " ~" + (minutes > 0 ? minutes + " minutes " : "") + seconds%60 + " seconds");
    }
}