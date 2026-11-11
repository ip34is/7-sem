/** Завдання 3: два мікроавтобуси на приміському маршруті (час у хвилинах). */
public class Task3Minibus {
    static final double DAY = 600; // 10 годин роботи
    static final int DAYS = 40, FARE = 20;
    static final String[] BOARDING = {"посадка в A на 1", "посадка в A на 2", "посадка в B на 1",
        "посадка в B на 2"};

    record Day(double queueWait, double inBus, int boarded, int lost, int revenue) {
    }

    static Day day(int seats) throws Exception {
        Sim s = new Sim(Nets.CreateNetMinibus(seats)).track(BOARDING).run(DAY);
        int boarded = 0; // сіли в мікроавтобус і заплатили за проїзд
        for (String t : BOARDING) {
            boarded += s.fired(t);
        }
        int lost = s.mark("пішли з зупинки 1") + s.mark("пішли з зупинки 2");
        double queue = s.mean("черга на зупинці 1") + s.mean("черга на зупинці 2");
        double seated = s.mean("пасажири в A") + s.mean("пасажири в B");
        // середній час очікування = сумарне очікування (Σ M·Δt) / кількість пасажирів, що сіли
        return new Day(queue * DAY / boarded, seated * DAY / boarded, boarded, lost,
                FARE * (boarded - lost));
    }

    public static void main(String[] args) throws Exception {
        System.out.printf("Маршрутки: %d днів по %.0f хв для кожного n%n", DAYS, DAY);
        System.out.println("  n | очікування в черзі, хв | у салоні, хв | сіли | пішли "
                + "| оплата, грн | недоотримано, грн | виручка, грн");
        int best = 0;
        double bestWait = Double.MAX_VALUE;
        for (int seats = 5; seats <= 25; seats += 5) {
            double wait = 0, inBus = 0, boarded = 0, lost = 0, revenue = 0, revenue2 = 0;
            for (int d = 0; d < DAYS; d++) {
                Day r = day(seats);
                wait += r.queueWait / DAYS;
                inBus += r.inBus / DAYS;
                boarded += (double) r.boarded / DAYS;
                lost += (double) r.lost / DAYS;
                revenue += (double) r.revenue / DAYS;
                revenue2 += (double) r.revenue * r.revenue / DAYS;
            }
            double error = Math.sqrt((revenue2 - revenue * revenue) / (DAYS - 1));
            System.out.printf(" %2d | %22.2f | %12.3f | %4.0f | %5.0f | %11.0f | %17.0f "
                    + "| %7.0f ± %.0f%n", seats, wait, inBus, boarded, lost, FARE * boarded,
                    FARE * lost, revenue, error);
            if (wait < bestWait) {
                bestWait = wait;
                best = seats;
            }
        }
        System.out.printf("Найменше очікування в черзі — при n = %d: %.2f хв%n", best, bestWait);
        System.out.println("Виручка = плата всіх, хто сів, − недоотримане від тих, хто пішов; ± — "
                + "стандартна похибка середнього за днями");
    }
}
