package co.teamsphere.api.helpers;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class TestAppender extends AppenderBase<ILoggingEvent> {
    private final List<ILoggingEvent> logEvents = new CopyOnWriteArrayList<>();

    @Override
    protected void append(ILoggingEvent eventObject) {
        logEvents.add(eventObject);
    }

    public List<ILoggingEvent> getLogEvents() {
        return logEvents;
    }

    public void clearEvents() {
        logEvents.clear();
    }
}
