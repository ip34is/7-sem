import java.util.ArrayList;
import java.util.List;
import ua.stetsenkoinna.petriobj.PetriNet;
import ua.stetsenkoinna.petriobj.PetriObjModel;
import ua.stetsenkoinna.petriobj.PetriP;
import ua.stetsenkoinna.petriobj.PetriSim;
import ua.stetsenkoinna.petriobj.PetriT;
import ua.stetsenkoinna.petriobj.StateTime;

/**
 * Імітація мережі Петрі: Петрі-об'єкт PetriSim у моделі PetriObjModel, яка просуває час
 * до найближчої події і рахує середні за часом значення маркерів і зайнятості переходів.
 */
final class Sim {
    final PetriNet net;
    double time;

    Sim(PetriNet net) {
        this.net = net;
    }

    /** Запам'ятовувати моменти входу і виходу маркерів переходу (щоб рахувати запуски). */
    Sim track(String... transitions) {
        for (String name : transitions) {
            t(name).setMoments(true);
        }
        return this;
    }

    Sim run(double time) {
        this.time = time;
        ArrayList<PetriSim> objects = new ArrayList<>(List.of(new PetriSim(net, new StateTime())));
        PetriObjModel model = new PetriObjModel(objects);
        model.setIsProtokol(false);
        model.go(time);
        return this;
    }

    PetriP p(String name) {
        for (PetriP place : net.getListP()) {
            if (place.getName().equals(name)) {
                return place;
            }
        }
        throw new IllegalArgumentException("немає позиції " + name);
    }

    PetriT t(String name) {
        for (PetriT transition : net.getListT()) {
            if (transition.getName().equals(name)) {
                return transition;
            }
        }
        throw new IllegalArgumentException("немає переходу " + name);
    }

    /** Кількість маркерів у позиції в кінці моделювання. */
    int mark(String place) {
        return p(place).getMark();
    }

    /** Середня за часом кількість маркерів у позиції. */
    double mean(String place) {
        return p(place).getMean();
    }

    /** Середня за часом кількість маркерів, що одночасно перебувають у переході. */
    double busy(String transition) {
        return t(transition).getMean();
    }

    /** Скільки разів маркери вийшли з переходу (потрібен track). */
    int fired(String transition) {
        return t(transition).getOutMoments().size();
    }

    /** Моменти виходу маркерів з переходу (потрібен track). */
    List<Double> exits(String transition) {
        return t(transition).getOutMoments();
    }
}
