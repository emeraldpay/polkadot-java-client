package io.emeraldpay.polkaj.scaletypes;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Runtime Metadata, which defines all available actions and types for the blockchain.
 * Available through state_getMetadata RPC.
 *
 * Reference: https://github.com/polkadot-js/api/blob/master/packages/types/src/interfaces/metadata/definitions.ts
 */
public class Metadata {

    private Integer magic;
    private Integer version;
    private List<Module> modules;

    public Integer getMagic() {
        return magic;
    }

    public void setMagic(Integer magic) {
        this.magic = magic;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public List<Module> getModules() {
        return modules;
    }

    public void setModules(List<Module> modules) {
        this.modules = modules;
    }

    public Optional<Module> findModule(String name) {
        if (modules == null) {
            return Optional.empty();
        }
        return getModules().stream()
                .filter(it -> it.getName().equals(name))
                .findAny();
    }

    public Optional<Call> findCall(String moduleName, String callName) {
        return findModule(moduleName)
                .flatMap((m) -> m.findCall(callName));
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Metadata)) return false;
        Metadata metadata = (Metadata) o;
        return Objects.equals(magic, metadata.magic) &&
                Objects.equals(version, metadata.version) &&
                Objects.equals(modules, metadata.modules);
    }

    @Override
    public final int hashCode() {
        return Objects.hash(magic, version, modules);
    }

    public static class Module {
        private String name;
        private Storage storage;
        private List<Call> calls;
        private List<Event> events;
        private List<Constant> constants;
        private List<Error> errors;
        private Integer index;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public Storage getStorage() {
            return storage;
        }

        public void setStorage(Storage storage) {
            this.storage = storage;
        }

        public List<Call> getCalls() {
            return calls;
        }

        public void setCalls(List<Call> calls) {
            this.calls = calls;
        }

        public List<Event> getEvents() {
            return events;
        }

        public void setEvents(List<Event> events) {
            this.events = events;
        }

        public List<Constant> getConstants() {
            return constants;
        }

        public void setConstants(List<Constant> constants) {
            this.constants = constants;
        }

        public List<Error> getErrors() {
            return errors;
        }

        public void setErrors(List<Error> errors) {
            this.errors = errors;
        }

        public Integer getIndex() {
            return index;
        }

        public void setIndex(Integer index) {
            this.index = index;
        }

        public Optional<Call> findCall(String name) {
            if (calls == null) {
                return Optional.empty();
            }
            return calls.stream()
                    .filter(it -> it.getName().equals(name))
                    .findAny();
        }

        @Override
        public final boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Module)) return false;
            Module module = (Module) o;
            return Objects.equals(name, module.name) &&
                    Objects.equals(storage, module.storage) &&
                    Objects.equals(calls, module.calls) &&
                    Objects.equals(events, module.events) &&
                    Objects.equals(constants, module.constants) &&
                    Objects.equals(errors, module.errors) &&
                    Objects.equals(index, module.index);
        }

        @Override
        public final int hashCode() {
            return Objects.hash(name, storage, calls, events, constants, errors, index);
        }
    }

    public static class Storage {
        private String prefix;
        private List<Entry> entries;

        public String getPrefix() {
            return prefix;
        }

        public void setPrefix(String prefix) {
            this.prefix = prefix;
        }

        public List<Entry> getEntries() {
            return entries;
        }

        public void setEntries(List<Entry> entries) {
            this.entries = entries;
        }

        @Override
        public final boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Storage)) return false;
            Storage storage = (Storage) o;
            return Objects.equals(prefix, storage.prefix) &&
                    Objects.equals(entries, storage.entries);
        }

        @Override
        public final int hashCode() {
            return Objects.hash(prefix, entries);
        }

        public static class Entry {
            private String name;
            private Modifier modifier;
            private Type<?> type;
            private byte[] defaults;
            private List<String> documentation;

            public String getName() {
                return name;
            }

            public void setName(String name) {
                this.name = name;
            }

            public Modifier getModifier() {
                return modifier;
            }

            public void setModifier(Modifier modifier) {
                this.modifier = modifier;
            }

            public Type<?> getType() {
                return type;
            }

            public void setType(Type<?> type) {
                this.type = type;
            }

            public byte[] getDefaults() {
                return defaults;
            }

            public void setDefaults(byte[] defaults) {
                this.defaults = defaults;
            }

            public List<String> getDocumentation() {
                return documentation;
            }

            public void setDocumentation(List<String> documentation) {
                this.documentation = documentation;
            }

            @Override
            public final boolean equals(Object o) {
                if (this == o) return true;
                if (!(o instanceof Entry)) return false;
                Entry entry = (Entry) o;
                return Objects.equals(name, entry.name) &&
                        modifier == entry.modifier &&
                        Objects.equals(type, entry.type) &&
                        Arrays.equals(defaults, entry.defaults) &&
                        Objects.equals(documentation, entry.documentation);
            }

            @Override
            public final int hashCode() {
                int result = Objects.hash(name, modifier, type, documentation);
                result = 31 * result + Arrays.hashCode(defaults);
                return result;
            }
        }

        public static enum Modifier {
            OPTIONAL, DEFAULT, REQUIRED
        }

        public static enum Hasher {
            BLAKE2_128,
            BLAKE2_256,
            BLAKE2_256_CONCAT,
            TWOX_128,
            TWOX_256,
            TWOX_64_CONCAT,
            IDENTITY
        }

        public static enum TypeId {
            PLAIN(String.class),
            MAP(MapDefinition.class),
            DOUBLEMAP(DoubleMapDefinition.class);

            private final Class<?> clazz;

            TypeId(Class<?> clazz) {
                this.clazz = clazz;
            }

            public Class<?> getClazz() {
                return clazz;
            }
        }

        public abstract static class Type<T> {
            private final T value;

            public Type(T value) {
                this.value = value;
            }

            public abstract TypeId getId();

            public T get() {
                return value;
            }

            @SuppressWarnings("unchecked")
            public <X> Type<X> cast(Class<X> clazz) {
                if (clazz.isAssignableFrom(getId().getClazz())) {
                    return (Type<X>) this;
                }
                throw new ClassCastException("Cannot cast " + getId().getClazz() + " to " + clazz);
            }

            @Override
            public final boolean equals(Object o) {
                if (this == o) return true;
                if (!(o instanceof Type)) return false;
                Type<?> type = (Type<?>) o;
                return Objects.equals(value, type.value);
            }

            @Override
            public final int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class PlainType extends Type<String> {
            public PlainType(String value) {
                super(value);
            }

            @Override
            public TypeId getId() {
                return TypeId.PLAIN;
            }
        }

        public static class MapDefinition {
            private Hasher hasher;
            private String key;
            private String type;
            private boolean iterable;

            public Hasher getHasher() {
                return hasher;
            }

            public void setHasher(Hasher hasher) {
                this.hasher = hasher;
            }

            public String getKey() {
                return key;
            }

            public void setKey(String key) {
                this.key = key;
            }

            public String getType() {
                return type;
            }

            public void setType(String type) {
                this.type = type;
            }

            public boolean isIterable() {
                return iterable;
            }

            public void setIterable(boolean iterable) {
                this.iterable = iterable;
            }

            @Override
            public final boolean equals(Object o) {
                if (this == o) return true;
                if (!(o instanceof MapDefinition)) return false;
                MapDefinition that = (MapDefinition) o;
                return iterable == that.iterable &&
                        hasher == that.hasher &&
                        Objects.equals(key, that.key) &&
                        Objects.equals(type, that.type);
            }

            @Override
            public final int hashCode() {
                return Objects.hash(hasher, key, type, iterable);
            }
        }

        public static class MapType extends Type<MapDefinition> {
            public MapType(MapDefinition value) {
                super(value);
            }

            @Override
            public TypeId getId() {
                return TypeId.MAP;
            }
        }

        public static class DoubleMapDefinition {
            private Hasher firstHasher;
            private String firstKey;
            private Hasher secondHasher;
            private String secondKey;
            private String type;

            public Hasher getFirstHasher() {
                return firstHasher;
            }

            public void setFirstHasher(Hasher firstHasher) {
                this.firstHasher = firstHasher;
            }

            public String getFirstKey() {
                return firstKey;
            }

            public void setFirstKey(String firstKey) {
                this.firstKey = firstKey;
            }

            public String getSecondKey() {
                return secondKey;
            }

            public void setSecondKey(String secondKey) {
                this.secondKey = secondKey;
            }

            public String getType() {
                return type;
            }

            public void setType(String type) {
                this.type = type;
            }

            public Hasher getSecondHasher() {
                return secondHasher;
            }

            public void setSecondHasher(Hasher secondHasher) {
                this.secondHasher = secondHasher;
            }

            @Override
            public final boolean equals(Object o) {
                if (this == o) return true;
                if (!(o instanceof DoubleMapDefinition)) return false;
                DoubleMapDefinition that = (DoubleMapDefinition) o;
                return firstHasher == that.firstHasher &&
                        Objects.equals(firstKey, that.firstKey) &&
                        Objects.equals(secondKey, that.secondKey) &&
                        Objects.equals(type, that.type) &&
                        secondHasher == that.secondHasher;
            }

            @Override
            public final int hashCode() {
                return Objects.hash(firstHasher, firstKey, secondKey, type, secondHasher);
            }
        }

        public static class DoubleMapType extends Type<DoubleMapDefinition> {
            public DoubleMapType(DoubleMapDefinition value) {
                super(value);
            }

            @Override
            public TypeId getId() {
                return TypeId.DOUBLEMAP;
            }
        }
    }

    public static class Call {
        private int index;
        private String name;
        private List<Arg> arguments;
        private List<String> documentation;

        public int getIndex() {
            return index;
        }

        public void setIndex(int index) {
            this.index = index;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public List<Arg> getArguments() {
            return arguments;
        }

        public void setArguments(List<Arg> arguments) {
            this.arguments = arguments;
        }

        public List<String> getDocumentation() {
            return documentation;
        }

        public void setDocumentation(List<String> documentation) {
            this.documentation = documentation;
        }

        @Override
        public final boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Call)) return false;
            Call call = (Call) o;
            return Objects.equals(name, call.name) &&
                    Objects.equals(index, call.index) &&
                    Objects.equals(arguments, call.arguments) &&
                    Objects.equals(documentation, call.documentation);
        }

        @Override
        public final int hashCode() {
            return Objects.hash(name, index, arguments, documentation);
        }

        public static class Arg {
            private String name;
            private String type;

            public String getName() {
                return name;
            }

            public void setName(String name) {
                this.name = name;
            }

            public String getType() {
                return type;
            }

            public void setType(String type) {
                this.type = type;
            }

            @Override
            public final boolean equals(Object o) {
                if (this == o) return true;
                if (!(o instanceof Arg)) return false;
                Arg arg = (Arg) o;
                return Objects.equals(name, arg.name) &&
                        Objects.equals(type, arg.type);
            }

            @Override
            public final int hashCode() {
                return Objects.hash(name, type);
            }
        }
    }

    public static class Event {
        private String name;
        private List<String> arguments;
        private List<String> documentation;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public List<String> getArguments() {
            return arguments;
        }

        public void setArguments(List<String> arguments) {
            this.arguments = arguments;
        }

        public List<String> getDocumentation() {
            return documentation;
        }

        public void setDocumentation(List<String> documentation) {
            this.documentation = documentation;
        }

        @Override
        public final boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Event)) return false;
            Event event = (Event) o;
            return Objects.equals(name, event.name) &&
                    Objects.equals(arguments, event.arguments) &&
                    Objects.equals(documentation, event.documentation);
        }

        @Override
        public final int hashCode() {
            return Objects.hash(name, arguments, documentation);
        }
    }

    public static class Constant {
        private String name;
        private String type;
        private byte[] value;
        private List<String> documentation;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public byte[] getValue() {
            return value;
        }

        public void setValue(byte[] value) {
            this.value = value;
        }

        public List<String> getDocumentation() {
            return documentation;
        }

        public void setDocumentation(List<String> documentation) {
            this.documentation = documentation;
        }

        @Override
        public final boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Constant)) return false;
            Constant constant = (Constant) o;
            return Objects.equals(name, constant.name) &&
                    Objects.equals(type, constant.type) &&
                    Arrays.equals(value, constant.value) &&
                    Objects.equals(documentation, constant.documentation);
        }

        @Override
        public final int hashCode() {
            int result = Objects.hash(name, type, documentation);
            result = 31 * result + Arrays.hashCode(value);
            return result;
        }
    }

    public static class Error {
        private String name;
        private List<String> documentation;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public List<String> getDocumentation() {
            return documentation;
        }

        public void setDocumentation(List<String> documentation) {
            this.documentation = documentation;
        }

        @Override
        public final boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Error)) return false;
            Error error = (Error) o;
            return Objects.equals(name, error.name) &&
                    Objects.equals(documentation, error.documentation);
        }

        @Override
        public final int hashCode() {
            return Objects.hash(name, documentation);
        }
    }

    @Override
    public String toString() {
        return "Metadata{" +
                "magic=" + magic +
                ", version=" + version +
                '}';
    }
}
