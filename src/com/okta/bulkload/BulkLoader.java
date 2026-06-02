package com.okta.bulkload;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.okta.sdk.resource.api.UserApi;
import com.okta.sdk.resource.client.ApiException;
import com.okta.sdk.resource.model.CreateUserRequest;
import com.okta.sdk.resource.model.Error;
import com.okta.sdk.resource.model.ErrorCause;
import com.okta.sdk.resource.model.User;
import com.okta.sdk.resource.model.UserCredentialsWritable;
import com.okta.sdk.resource.model.UserProfile;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.csv.QuoteMode;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class BulkLoader {
    static final Properties configuration = new Properties();
    static final ObjectMapper errorMapper = new ObjectMapper();
    static AtomicInteger successCount = new AtomicInteger(0);
    static AtomicInteger errorCount = new AtomicInteger(0);
    static CSVPrinter errorRecordPrinter;
    static CSVPrinter rateLimitFailurePrinter;
    static CSVPrinter successRecordPrinter;
    static volatile boolean noMoreRecordsBeingAdded = false;
    static String[] successHeaders;
    static String[] errorHeaders;
    static String csvFileArg;
    static UserApi userApi;

    private static String oktaClientErrorHint(Throwable error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            String message = t.getMessage();
            if (message != null && message.contains("invalid_dpop_proof")) {
                return "Your Okta service app requires DPoP, but the token handshake did not complete. "
                        + "In Admin Console: Applications → your service app → General → "
                        + "turn off \"Require Demonstrating Proof-of-Possession (DPoP)\", then try again.";
            }
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Start : " + new Date());
        System.out.println();
        long startTime = System.currentTimeMillis();

        if (args.length < 2) {
            System.out.println(new Date() + " : **ERROR** : Missing arguments");
            System.out.println("Run using: java -jar DeCare-user-import.jar <config_file> <csv_file>");
            System.exit(-1);
        }

        try {
            configuration.load(new FileInputStream(args[0]));
            csvFileArg = args[1];
        } catch (Exception e) {
            System.out.println("Error reading configuration. Exiting...");
            System.exit(-1);
        }

        try {
            userApi = new UserApi(OktaClientFactory.create(configuration));
        } catch (Exception e) {
            System.out.println("Error creating Okta client: " + e.getMessage());
            String hint = oktaClientErrorHint(e);
            if (hint != null) {
                System.out.println(hint);
            }
            System.exit(-1);
        }

        int dotIndex = csvFileArg.lastIndexOf('.');
        if (dotIndex < 0) {
            System.out.println("CSV file path must include a file extension.");
            System.exit(-1);
        }

        String filePrefix = csvFileArg.substring(0, dotIndex);
        String successFile = filePrefix + "_success.csv";
        String errorFile = filePrefix + "_reject.csv";
        String rateLimitFile = filePrefix + "_replay.csv";
        errorHeaders = (configuration.getProperty("csvHeaderRow") + ",errorCode,errorCause").split(",");
        successHeaders = (configuration.getProperty("csvHeaderRow") + ",id,status").split(",");
        int numConsumers = Integer.parseInt(configuration.getProperty("numConsumers", "1"));
        int bufferSize = Integer.parseInt(configuration.getProperty("bufferSize", "10000"));

        CSVFormat errorFormat = CSVFormat.RFC4180.withDelimiter(',')
                .withQuote('"').withQuoteMode(QuoteMode.ALL).withHeader(errorHeaders);
        CSVFormat successFormat = CSVFormat.RFC4180.withDelimiter(',')
                .withQuote('"').withQuoteMode(QuoteMode.ALL).withHeader(successHeaders);

        successRecordPrinter = new CSVPrinter(new FileWriter(successFile, StandardCharsets.UTF_8), successFormat);
        errorRecordPrinter = new CSVPrinter(new FileWriter(errorFile, StandardCharsets.UTF_8), errorFormat);
        rateLimitFailurePrinter = new CSVPrinter(new FileWriter(rateLimitFile, StandardCharsets.UTF_8), errorFormat);
        successRecordPrinter.flush();
        errorRecordPrinter.flush();
        rateLimitFailurePrinter.flush();

        BlockingQueue<CSVRecord> queue = new LinkedBlockingQueue<>(bufferSize);

        Thread producer = new Thread(new Producer(queue));
        producer.start();

        Thread[] consumers = new Thread[numConsumers];
        for (int i = 0; i < numConsumers; i++) {
            consumers[i] = new Thread(new Consumer(queue));
            consumers[i].start();
        }

        producer.join();
        for (Thread consumer : consumers) {
            consumer.join();
        }

        successRecordPrinter.close();
        errorRecordPrinter.close();
        rateLimitFailurePrinter.close();

        System.out.println();
        System.out.println("Successfully added " + successCount + " user(s)");
        System.out.println("Error in processing " + errorCount + " user(s)");
        System.out.println();
        System.out.println("Done : " + new Date());
        long duration = (System.currentTimeMillis() - startTime) / 1000;
        System.out.println("Total time taken = " + duration + " seconds");
    }
}

class Producer implements Runnable {
    private final BlockingQueue<CSVRecord> queue;
    private final CSVFormat format;

    Producer(BlockingQueue<CSVRecord> queue) {
        this.queue = queue;
        format = CSVFormat.RFC4180.withHeader().withDelimiter(',');
    }

    @Override
    public void run() {
        try (Reader reader = new InputStreamReader(
                new FileInputStream(BulkLoader.csvFileArg), StandardCharsets.UTF_8);
             CSVParser parser = new CSVParser(reader, format)) {
            for (CSVRecord record : parser) {
                queue.put(record);
            }
        } catch (Exception excp) {
            System.out.println(excp.getLocalizedMessage());
        } finally {
            BulkLoader.noMoreRecordsBeingAdded = true;
        }
    }
}

class Consumer implements Runnable {
    private final BlockingQueue<CSVRecord> queue;
    private final String[] csvHeaders;
    private final String csvLoginField;
    private final String csvPasswordField;
    private final String saltOrder;
    private final boolean activateUsers;
    private final String groupIDs;

    Consumer(BlockingQueue<CSVRecord> queue) {
        this.queue = queue;
        csvHeaders = BulkLoader.configuration.getProperty("csvHeaderRow").split(",");
        csvLoginField = BulkLoader.configuration.getProperty("csvLoginField");
        csvPasswordField = BulkLoader.configuration.getProperty("csvPasswordField");
        saltOrder = BulkLoader.configuration.getProperty("saltOrder");
        activateUsers = Boolean.parseBoolean(BulkLoader.configuration.getProperty("activateUsers", "true"));
        groupIDs = BulkLoader.configuration.getProperty("groupIDs");
    }

    @Override
    public void run() {
        try {
            while (true) {
                if (BulkLoader.noMoreRecordsBeingAdded && queue.isEmpty()) {
                    break;
                }
                consume(queue.take());
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } catch (Exception excp) {
            System.out.println(excp.getLocalizedMessage());
        }
    }

    void consume(CSVRecord csvRecord) throws IOException {
        try {
            CreateUserRequest request = buildCreateUserRequest(csvRecord);
            User created = BulkLoader.userApi.createUser(request, activateUsers, null, null);
            handleSuccessResponse(created, csvRecord);
            int count = BulkLoader.successCount.incrementAndGet();
            if (count % 100 == 0) {
                System.out.print(".");
            }
        } catch (ApiException e) {
            boolean rateLimited = e.getCode() == 429;
            handleErrorResponse(rateLimited, e, csvRecord);
        } catch (Exception e) {
            handleErrorResponse(false, e.getMessage(), "Exception", csvRecord);
        }
    }

    private CreateUserRequest buildCreateUserRequest(CSVRecord csvRecord) {
        UserProfile profile = new UserProfile();
        profile.setLogin(csvRecord.get(csvLoginField));

        for (String headerColumn : csvHeaders) {
            if (!headerColumn.equalsIgnoreCase(csvPasswordField)) {
                String oktaField = BulkLoader.configuration.getProperty("csvHeader." + headerColumn);
                if (oktaField != null) {
                    profile.getAdditionalProperties().put(oktaField, csvRecord.get(headerColumn));
                }
            }
        }

        CreateUserRequest request = new CreateUserRequest();
        request.setProfile(profile);

        if (groupIDs != null && !groupIDs.trim().isEmpty()) {
            List<String> groupIdList = new ArrayList<>();
            for (String groupId : groupIDs.split(",")) {
                if (!groupId.trim().isEmpty()) {
                    groupIdList.add(groupId.trim());
                }
            }
            if (!groupIdList.isEmpty()) {
                request.setGroupIds(groupIdList);
            }
        }

        String shaValue = csvRecord.get(csvPasswordField);
        UserCredentialsWritable credentials =
                ImportedPasswordSupport.credentialsFromCsv(shaValue, saltOrder);
        request.setCredentials(credentials);
        return request;
    }

    private void handleErrorResponse(boolean isRateLimitError, ApiException e, CSVRecord csvRecord)
            throws IOException {
        String errorCode = "HTTP Response code : " + e.getCode();
        String errorCause = e.getMessage();

        if (e.getResponseBody() != null && !e.getResponseBody().isEmpty()) {
            try {
                Error error = BulkLoader.errorMapper.readValue(e.getResponseBody(), Error.class);
                if (error.getErrorCode() != null) {
                    errorCode = error.getErrorCode();
                }
                List<ErrorCause> causes = error.getErrorCauses();
                if (causes != null && !causes.isEmpty() && causes.get(0).getErrorSummary() != null) {
                    errorCause = causes.get(0).getErrorSummary();
                } else if (error.getErrorSummary() != null) {
                    errorCause = error.getErrorSummary();
                }
            } catch (Exception ignored) {
                // keep HTTP code / message fallback
            }
        }

        writeErrorRow(isRateLimitError, errorCode, errorCause, csvRecord);
    }

    private void handleErrorResponse(
            boolean isRateLimitError,
            String errorCause,
            String errorCode,
            CSVRecord csvRecord) throws IOException {
        writeErrorRow(isRateLimitError, errorCode, errorCause, csvRecord);
    }

    private void writeErrorRow(
            boolean isRateLimitError,
            String errorCode,
            String errorCause,
            CSVRecord csvRecord) throws IOException {
        Map<String, String> values = csvRecord.toMap();
        values.put("errorCode", errorCode);
        values.put("errorCause", errorCause);

        CSVPrinter printer = isRateLimitError ? BulkLoader.rateLimitFailurePrinter : BulkLoader.errorRecordPrinter;
        synchronized (printer) {
            for (String header : BulkLoader.errorHeaders) {
                printer.print(values.get(header));
            }
            printer.println();
            printer.flush();
        }
        BulkLoader.errorCount.incrementAndGet();
    }

    private void handleSuccessResponse(User user, CSVRecord csvRecord) throws IOException {
        Map<String, String> values = csvRecord.toMap();
        values.put("id", user.getId());
        values.put("status", user.getStatus() != null ? user.getStatus().name() : "");

        synchronized (BulkLoader.successRecordPrinter) {
            for (String header : BulkLoader.successHeaders) {
                BulkLoader.successRecordPrinter.print(values.get(header));
            }
            BulkLoader.successRecordPrinter.println();
            BulkLoader.successRecordPrinter.flush();
        }
    }
}
