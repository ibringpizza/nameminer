package nameminer;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import static nameminer.NameMiner.waitForConnection;
import org.apache.commons.net.whois.WhoisClient;


public class Avail extends Thread{
    List<String> domains = new ArrayList<>();
    boolean returnRegDate = false;
    boolean onlyAvail = false;
    Predicate<Boolean> p = null;
    static String endpoint = "https://rdap.verisign.com/com/v1/domain/";
    
    public Avail(List<String> domains, boolean regDate){
        this.domains = domains;
        this.returnRegDate = regDate;
    }
    
    public static boolean checkAvail(String domain){
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
                    NameMiner.waitForConnection();
                }
                Matcher match = p.matcher(result.substring(0, 12));
                whois.disconnect();
                fin = true;
                if(match.find())return true;
            } catch (IOException ex) {
                Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
            }catch(Exception ex){
                NameMiner.waitForConnection();
            }
        }
        return false;
    }
    
    /*
    public static boolean checkAvail(String domain){
        
        HttpsURLConnection connect;
        URL url = null;
        try {
            url = new URL(endpoint + domain);
        } catch (MalformedURLException ex) {
            Logger.getLogger(Avail.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            connect = (HttpsURLConnection) url.openConnection();
            connect.setRequestMethod("GET");
            connect.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36 OPR/68.0.3618.125");
            connect.setRequestProperty("Origin", "https://lookup.icann.org");
            connect.setRequestProperty("Host", "rdap.verisign.com");
            connect.setRequestProperty("Accept", "application/json, application/rdap+json");
            connect.setRequestProperty("Accept-Encoding", "gzip, deflate, br");
            connect.setRequestProperty("Accept-Language", "en-US,en;q=0.9");
            if(connect.getResponseCode() == 404)
                return true;
            else if(connect.getResponseCode() == 200)
                return false;
        } catch (ProtocolException ex) {
            Logger.getLogger(Avail.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Avail.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        return false;
    }
    */
    
    public String getWhois(String domain){
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
                    NameMiner.waitForConnection();
                }
                Matcher match = p.matcher(result.substring(0, 12));
                whois.disconnect();
                fin = true;
                if(match.find())return "";
                String clean = result.substring(0, result.indexOf("<<<")+3).replaceAll("   ", "").replaceAll(" <<<", "").replaceAll(">>> ", "");
                clean = clean.replaceAll("\r\nDNSSEC: unsigned", "").replaceAll("\r\nURL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/", "");
                return clean;
            } catch (IOException ex) {
                Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
            }catch(Exception ex){
                NameMiner.waitForConnection();
            }
        }
        return "";
    }
    
    static String getRegDate(String domain){
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
                    return (domain + ": " + match.group(2));
            } catch (IOException ex) {
                Logger.getLogger(NameMiner.class.getName()).log(Level.SEVERE, null, ex);
            } catch (Exception ex) {
                waitForConnection();
            }
        }
        return "";
    }
    
    public void run(){
        for(String domain : domains){
            if(!returnRegDate){
                if(checkAvail(domain)){
                    synchronized(this){
                        NameMiner.available_domains.add(domain);
                    }
                }
            }else{
                String date = getRegDate(domain);
                synchronized(this){
                    if(date.length() > 0)
                        NameMiner.available_domains.add(date);
                }
            }
            
        }
    }
    
    /* write whois
    public void run(){
        BufferedWriter bw = null;
        System.out.println("Thread #" + Thread.currentThread().getId() + " is running");
        try {
            StringBuilder sb = new StringBuilder();
            bw = new BufferedWriter(new FileWriter("C:\\Users\\leand\\Downloads\\whois_data.txt", true));
            for(int i = 0; i<domains.size(); i++){
                String whois = getWhois(domains.get(i) + ".com");
                if(whois.length() > 0)
                    sb.append(whois + "\n");
                if(i%100==0){
                    synchronized(this){
                        bw.write(sb.toString());
                        bw.flush();
                    }
                    sb = new StringBuilder();
                }
            }
            synchronized(this){
                bw.write(sb.toString());
                bw.flush();
            }
        } catch (IOException ex) {
            Logger.getLogger(Avail.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                bw.close();
            } catch (IOException ex) {
                Logger.getLogger(Avail.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    */
}
