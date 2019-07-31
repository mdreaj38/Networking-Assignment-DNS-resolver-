import java.nio.charset.StandardCharsets;
import java.util.*;
import java.io.*;
import java.lang.*;
import java.net.*;
class _Requests{ // store the info of Requests
    String name,type,Class;
    public _Requests(){
        name = "";
        type = "";
        Class = "";
    }
}
class _Response{  //store the info of responses
    String name,type,Class;
    int TTL;
    String answer_ip;
    public _Response(){
        name = "";
        type = "";
        Class = "";
        TTL = 0;
        answer_ip = "";
    }
}


class _Additional{ //store the info of additional info
    String name,type,Class, answer_ip;;
    int TTL;
    public _Additional(){
        name = "";
        type = "";
        Class = "";
        answer_ip = "";
        TTL = 0;
    }
}

class _Authoritative{// store the info of authoritative
    String name,type,Class,answer_ip;;
    int TTL;
    public _Authoritative(){
        name = "";
        type = "";
        Class = "";
        answer_ip = "";
        TTL = 0;
    }
}
class nope{
    public static Set<String> redund = new HashSet<String>();
    public static String domain;
}
public class Dns_resolver{

    public byte[] buffer = new byte[1024];

    public static String get_class(int type) {//return the class of response message
        String ret;
        if (type == 0) ret = "RESERVED";
        else if (type == 1) ret = "IN";
        else if (type == 2) ret = "Unassigned";
        else if (type == 3) ret = "CH";
        else if (type == 4) ret = "HS";
        else ret = "unrecognize";

        return ret;
    }

    public static String get_type(int type) { //return the type of response message
        String ret;
        if (type == 1) ret = "A";
        else if (type == 2) ret = "NS";
        else if (type == 5) ret = "CNAME";
        else if (type == 6) ret = "SOA";
        else if (type == 12) ret = "PTR";
        else ret = "unrecog";
        return ret;
    }

    public String nameScrape(int start) { //Input the starting indexex of domanin in message , and return the domanin name
        String ret = "";
        while (true) {
            String temp = String.format("%x", buffer[start]);
            if (temp.equals("c0")) {
                start++;
                if (!ret.equals("")) ret = ret + ".";
                ret = ret + nameScrape(buffer[start] & 0xFF);
                return ret;
            } else {
                int len = buffer[start] & 0xFF; //hexa to integer conversion
                if (len == 0) return ret;
                if (!ret.equals("")) ret = ret + ".";
                start++;
                int i = 0;
                while (i < len) {
                    ret += (char) buffer[start + i];
                    i++;
                }
                start = start + len;
            }
        }
    }

    public Set<String> resolve(String domain, String serverIP) throws IOException {
        Set<String> ip = new HashSet<String>();
        Set<String> admnIP = new HashSet<String>();
        // System.out.println("Request-> " + domain + "      " + serverIP);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeShort(0x1234); /*  An identifier(16 Bit) that is used to match the response message with the request message ,
        as the id of the response message is the same as the corresponding request message*/
        dos.writeShort(0x0000);// Write Query flag
        dos.writeShort(0x0001); // Question Count
        dos.writeShort(0x0000);// Answer Count:
        dos.writeShort(0x0000);// Authorititive Record Count
        dos.writeShort(0x0000);// _Additional Record Count:


        String[] domainParts = domain.split("\\.");
        for (int i = 0; i < domainParts.length; i++) {
            byte[] domainBytes = domainParts[i].getBytes("UTF-8");
            dos.writeByte(domainBytes.length);
            dos.write(domainBytes);
        }
        dos.writeByte(0x00);// end of message
        dos.writeShort(0x0001);// Type 0x01 = A (Host Request)
        dos.writeShort(0x0001);// Class 0x01 = IN
        byte[] Dns_Frame = baos.toByteArray();

        DatagramSocket socket = new DatagramSocket();//Send request
        socket.setSoTimeout(5000); //5 sec for timeout
        DatagramPacket DnsReqPacket = new DatagramPacket(Dns_Frame, Dns_Frame.length, InetAddress.getByName(serverIP), 53);
        socket.send(DnsReqPacket);
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        //waiting for response
        try {
            socket.receive(packet);
        } catch (SocketTimeoutException e) {
            System.out.println("Timeout");
            socket.close();
            return ip;
        }
        socket.close();
        int index = 0;
        String transaction_id = String.format("0x%x", buffer[index]) + String.format("%x", buffer[index + 1]);//extract the identifier
        index += 2;
        String flag = String.format("0x%x", buffer[index]) + String.format("%x", buffer[index + 1]);
        index += 2;
        String temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
        index += 2;
        int num_of_q = Integer.parseInt(temp, 16);
        temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
        index += 2;
        int num_of_a = Integer.parseInt(temp, 16);
        temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
        index += 2;
        int num_of_admin = Integer.parseInt(temp, 16);
        temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
        index += 2;
        int num_of__Additional = Integer.parseInt(temp, 16);
        byte[] temp_byte = new byte[1024];
        _Requests[] Qarr = new _Requests[num_of_q];
        for (int i = 0; i < num_of_q; i++) {
            Qarr[i] = new _Requests();
            Qarr[i].name = nameScrape(index);
            while (!String.format("%x", buffer[index]).equals("0") && !String.format("%x", buffer[index]).equals("c0"))
                index++;
            if (String.format("%x", buffer[index]).equals("c0")) index += 2;
            else if (String.format("%x", buffer[index]).equals("0")) index++;
            int x = 0;
            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
            index += 2;
            x = Integer.parseInt(temp, 16);
            Qarr[i].type = get_type(x);
            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
            index += 2;
            x = Integer.parseInt(temp, 16);
            Qarr[i].Class = get_class(x);
        }
        _Response[] Qanswer = new _Response[num_of_a];
        for (int i = 0; i < num_of_a; i++) {
            Qanswer[i] = new _Response();
            Qanswer[i].name = nameScrape(index);
            while (!String.format("%x", buffer[index]).equals("0") && !String.format("%x", buffer[index]).equals("c0"))
                index++;
            if (String.format("%x", buffer[index]).equals("c0")) index += 2;
            else if (String.format("%x", buffer[index]).equals("0")) index++;
            int x = 0;
            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
            index += 2;
            x = Integer.parseInt(temp, 16);
            Qanswer[i].type = get_type((int) x);
            if (Qanswer[i].type.equals("SOA")) {
                System.out.println(domain + " is erroneous");
                return ip;
            }
            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
            index += 2;
            x = Integer.parseInt(temp, 16);
            Qanswer[i].Class = get_class((int) x);
            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]) + String.format("%x", buffer[index + 2]) + String.format("%x", buffer[index + 3]);
            index += 4;
            x = Integer.parseInt(temp, 16);
            Qanswer[i].TTL = x;
            if (Qanswer[i].type.equals("CNAME")) {
                index += 2;
                Qanswer[i].answer_ip = nameScrape(index);
                while (!String.format("%x", buffer[index]).equals("0") && !String.format("%x", buffer[index]).equals("c0"))
                    index++;
                if (String.format("%x", buffer[index]).equals("c0")) index += 2;
                else if (String.format("%x", buffer[index]).equals("0")) index++;
            } else {
                temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
                index += 2;
                x = Integer.parseInt(temp, 16);
                int k = 0;
                while (k < x) {
                    temp = String.format("%d", buffer[index + k] & 0xFF);
                    Qanswer[i].answer_ip = Qanswer[i].answer_ip + temp;
                    if (k != x - 1) Qanswer[i].answer_ip = Qanswer[i].answer_ip + ".";
                    k++;
                }
                index += x;
            }
            if (Qanswer[i].type.equals("A")) ip.add(Qanswer[i].answer_ip);
            else if (Qanswer[i].type.equals("CNAME") && !nope.redund.contains(new String(Qanswer[i].answer_ip + "192.58.128.30"))) {
                Dns_resolver t_Resolver = new Dns_resolver();
                nope.redund.add(new String(Qanswer[i].answer_ip + "192.58.128.30"));
                Set<String> tt = t_Resolver.resolve(Qanswer[i].answer_ip, "192.58.128.30");
                if (tt != null) ip.addAll(tt);
            }
        }
        _Authoritative[] Qad = new _Authoritative[num_of_admin];
        for (int i = 0; i < num_of_admin; i++) {
            Qad[i] = new _Authoritative();
            Qad[i].name = nameScrape(index);
            while (!String.format("%x", buffer[index]).equals("c0") && !String.format("%x", buffer[index]).equals("0"))
                index++;
            if (String.format("%x", buffer[index]).equals("c0")) index += 2;
            else if (String.format("%x", buffer[index]).equals("0")) index++;
            int x = 0;
            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
            index += 2;
            x = Integer.parseInt(temp, 16);
            Qad[i].type = get_type((int) x);
            if (Qad[i].type.equals("SOA")) {
                System.out.println(domain + " is erroneous");
                return ip;
            }
            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
            index += 2;
            x = Integer.parseInt(temp, 16);
            Qad[i].Class = get_class((int) x);
            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]) + String.format("%x", buffer[index + 2]) + String.format("%x", buffer[index + 3]);
            index += 4;
            x = Integer.parseInt(temp, 16);
            Qad[i].TTL = x;

            if (Qad[i].type.equals("CNAME") || Qad[i].type.equals("NS")) {
                index += 2;
                Qad[i].answer_ip = nameScrape(index);
                while (!String.format("%x", buffer[index]).equals("c0") && !String.format("%x", buffer[index]).equals("0"))
                    index++;
                if (String.format("%x", buffer[index]).equals("c0")) index += 2;
                else if (String.format("%x", buffer[index]).equals("0")) index++;
            } else {
                temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
                index += 2;
                x = Integer.parseInt(temp, 16);
                int k = 0;
                while (k < x) {
                    temp = String.format("%d", buffer[index + k] & 0xFF);
                    Qad[i].answer_ip = Qad[i].answer_ip + temp;
                    if (k != x - 1) Qad[i].answer_ip = Qad[i].answer_ip + ".";
                    k++;
                }
                index += x;
            }
            if (Qad[i].type.equals("SOA")) {
                System.out.println(domain + "is erroneous");
                return ip;
            }
            if (Qad[i].type.equals("NS")) admnIP.add(Qad[i].answer_ip);
        }
        _Additional[] Q__Additional = new _Additional[num_of__Additional];

        for (int i = 0; i < num_of__Additional; i++) {
            Q__Additional[i] = new _Additional();
            Q__Additional[i].name = nameScrape(index);
            while (!String.format("%x", buffer[index]).equals("c0") && !String.format("%x", buffer[index]).equals("0"))
                index++;
            if (String.format("%x", buffer[index]).equals("c0")) index += 2;
            else if (String.format("%x", buffer[index]).equals("0")) index++;
            int x = 0;

            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
            index += 2;
            x = Integer.parseInt(temp, 16);
            Q__Additional[i].type = get_type((int) x);
            if (Q__Additional[i].type.equals("SOA")) {
                System.out.println(domain + " is erroneous");
                return ip;
            }
            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
            index += 2;
            x = Integer.parseInt(temp, 16);
            Q__Additional[i].Class = get_class((int) x);
            temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]) + String.format("%x", buffer[index + 2]) + String.format("%x", buffer[index + 3]);
            index += 4;
            x = Integer.parseInt(temp, 16);
            Q__Additional[i].TTL = x;
            if (Q__Additional[i].type.equals("CNAME")) {
                index += 2;

                Q__Additional[i].answer_ip = nameScrape(index);
                while (!String.format("%x", buffer[index]).equals("c0") && !String.format("%x", buffer[index]).equals("0"))
                    index++;

                if (String.format("%x", buffer[index]).equals("c0"))
                    index += 2;
                else if (String.format("%x", buffer[index]).equals("0")) index++;
            } else {
                temp = String.format("%x", buffer[index]) + String.format("%x", buffer[index + 1]);
                index += 2;
                x = Integer.parseInt(temp, 16);
                int k = 0;

                while (k < x) {
                    temp = String.format("%d", buffer[index + k] & 0xFF);
                    Q__Additional[i].answer_ip = Q__Additional[i].answer_ip + temp;
                    if (k != x - 1) Q__Additional[i].answer_ip = Q__Additional[i].answer_ip + ".";
                    k++;
                }


                index += x;
            }
            if (!nope.redund.contains(new String(domain + Q__Additional[i].answer_ip)) && Q__Additional[i].type.equals("A")) {

                if (admnIP.contains(Q__Additional[i].name)) admnIP.remove(Q__Additional[i].name);
                Dns_resolver t_Resolver = new Dns_resolver();
                nope.redund.add(new String(domain + Q__Additional[i].answer_ip));
                Set<String> ttemp = t_Resolver.resolve(domain, Q__Additional[i].answer_ip);
                if (ttemp != null) ip.addAll(ttemp);
            } else if (Q__Additional[i].type.equals("SOA"))
                System.out.println(domain + "is erroneous");
        }
        return ip;
    }


    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Argument missing");
            return;
        }
        nope.domain = args[0];
        Dns_resolver agg = new Dns_resolver();
        nope.redund.add(new String(nope.domain + "202.12.27.33"));
        Set<String> ip = agg.resolve(nope.domain, "202.12.27.33");

        if (ip.size() == 0) System.out.println(nope.domain + " = " + "does not exist");
        else {
            Iterator it = ip.iterator();
            while (it.hasNext())
                System.out.println(nope.domain + " : " + (String) it.next());
        }
    }
}
