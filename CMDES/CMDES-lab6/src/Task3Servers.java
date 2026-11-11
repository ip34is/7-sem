/** Завдання 3: багатопотокова обробка запитів на головному і допоміжному серверах (мс). */
public class Task3Servers {
    static final double TIME = 600_000; // 10 хвилин
    static final String[][] SERVERS = {{"головний", "16", "8"}, {"допоміжний", "8", "4"}};

    record Server(int received, int rejected, int done, double queue, double threads,
                  double cores, double inSystem, double time) {
    }

    static Server server(Sim s, String[] srv) {
        String l = " (" + srv[0] + ")";
        int threads = Integer.parseInt(srv[1]), cores = Integer.parseInt(srv[2]);
        // запити на сервері: у черзі, у потоці, на обчисленні, з результатом і на записі в БД
        double inSystem = s.mean("черга" + l) + s.mean("запит у потоці" + l)
                + s.mean("результат обчислено" + l) + s.busy("обчислення" + l)
                + s.busy("запис у БД" + l);
        int done = s.mark("відповідь надіслано" + l);
        return new Server(s.fired("на " + srv[0] + " сервер"), s.mark("відмовлено" + l), done,
                s.mean("черга" + l), threads - s.mean("вільні потоки" + l),
                cores - s.mean("вільні ядра" + l), inSystem, inSystem / (done / TIME));
    }

    static Sim run(double interval) throws Exception {
        return new Sim(Nets.CreateNetServers(interval))
                .track("на головний сервер", "на допоміжний сервер").run(TIME);
    }

    public static void main(String[] args) throws Exception {
        Sim s = run(10);
        System.out.printf("Сервери, T = %.0f мс, запит у середньому кожні 10 мс%n", TIME);
        double inSystem = 0;
        int done = 0;
        for (String[] srv : SERVERS) {
            Server r = server(s, srv);
            inSystem += r.inSystem;
            done += r.done;
            System.out.printf("Сервер %s: надійшло %d, відмовлено %d, оброблено %d%n", srv[0],
                    r.received, r.rejected, r.done);
            System.out.printf("  середня черга %.3f; зайнято потоків %.3f з %s, ядер %.3f з %s%n",
                    r.queue, r.threads, srv[1], r.cores, srv[2]);
            System.out.printf("  середній час обробки запиту: %.2f мс%n", r.time);
        }
        System.out.printf("Зайнято з'єднань з БД: %.3f з 10%n",
                10 - s.mean("вільні з'єднання з БД"));
        System.out.printf("Середній час обробки запиту для обох серверів: %.2f мс%n",
                inSystem / (done / TIME));

        System.out.println("\nЗалежність часу обробки від інтенсивності запитів:");
        System.out.println(" інтервал, мс | запитів/с | ядер головного | ядер допоміжного "
                + "| час: головний | допоміжний | відмов");
        for (double interval : new double[]{40, 20, 12, 10, 9, 8}) {
            Sim v = run(interval);
            Server a = server(v, SERVERS[0]), b = server(v, SERVERS[1]);
            System.out.printf(" %12.0f | %9.0f | %14.3f | %16.3f | %13.1f | %10.1f | %6d%n",
                    interval, 1000 / interval, a.cores, b.cores, a.time, b.time,
                    a.rejected + b.rejected);
        }
    }
}
