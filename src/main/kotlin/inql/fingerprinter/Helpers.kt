package inql.fingerprinter

class Helpers {
    companion object {
        data class EngineDetails(
            val name: String,
            val url: String,
            val ref: String,
            val technology: List<String>
        )

        val engines = mapOf(
            "apollo" to EngineDetails(
                "Apollo",
                "https://www.apollographql.com",
                "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/apollo.md",
                listOf("JavaScript", "Node.js", "TypeScript")
            ),
            "aws-appsync" to EngineDetails(
                "AWS AppSync",
                "https://aws.amazon.com/appsync",
                "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/appsync.md",
                listOf()
            ),
            "graphene" to EngineDetails(
                "Graphene",
                "https://graphene-python.org",
                "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/graphene.md",
                listOf("Python")
            ),
            "hasura" to EngineDetails(
                "Hasura",
                "https://hasura.io",
                "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/hasura.md",
                listOf("Haskell")
            ),
            "graphql-php" to EngineDetails(
                "GraphQL PHP",
                "https://webonyx.github.io/graphql-php",
                "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/graphql-php.md",
                listOf("PHP")
            ),
            "ruby-graphql" to EngineDetails(
                "Ruby GraphQL",
                "https://graphql-ruby.org",
                "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/graphql-ruby.md",
                listOf("Ruby")
            ),
            "hypergraphql" to EngineDetails(
                "HyperGraphQL",
                "https://www.hypergraphql.org",
                "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/hypergraphql.md",
                listOf("Java")
            ),
            "ariadne" to EngineDetails(
                "Ariadne",
                "https://ariadnegraphql.org",
                "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/ariadne.md",
                listOf("Python")
            ),
            "graphql-api-for-wp" to EngineDetails(
                "GraphQL API for Wordpress (Gato GraphQL)",
                "https://graphql-api.com",
                "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/graphql-api-for-wp.md",
                listOf("PHP")
            ),
            "wpgraphql" to EngineDetails(
            "WPGraphQL WordPress Plugin",
            "https://www.wpgraphql.com",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/wp-graphql.md",
            listOf("PHP")
            ),
            "gqlgen" to EngineDetails(
            "gqlgen - GraphQL for Go",
            "https://gqlgen.com",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/gqlgen.md",
            listOf("Go")
            ),
            "graphql-go" to EngineDetails(
            "graphql-go -GraphQL for Go",
            "https://raw.githubusercontent.com/graphql-go/graphql",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/graphql-go.md",
            listOf("Go")
            ),
            "graphql-java" to EngineDetails(
            "graphql-java - GraphQL for Java",
            "https://www.graphql-java.com",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/graphql-java.md",
            listOf("Java")
            ),
            "juniper" to EngineDetails(
            "Juniper - GraphQL for Rust",
            "https://graphql-rust.github.io",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/juniper.md",
            listOf("Rust")
            ),
            "sangria" to EngineDetails(
            "Sangria - GraphQL for Scala",
            "https://sangria-graphql.github.io",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/sangria.md",
            listOf("Scala")
            ),
            "flutter" to EngineDetails(
            "Flutter - GraphQL for Dart",
            "https://raw.githubusercontent.com/zino-app/graphql-flutter",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/gql-dart.md",
            listOf("Dart")
            ),
            "dianajl" to EngineDetails(
            "Diana.jl - GraphQL for Julia",
            "https://raw.githubusercontent.com/neomatrixcode/Diana.jl",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/diana.md",
            listOf("Julia")
            ),
            "strawberry" to EngineDetails(
            "Strawberry - GraphQL for Python",
            "https://raw.githubusercontent.com/strawberry-graphql/strawberry",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/strawberry.md",
            listOf("Python")
            ),
            "tartiflette" to EngineDetails(
            "tartiflette - GraphQL for Python",
            "https://raw.githubusercontent.com/tartiflette/tartiflette",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/tartiflette.md",
            listOf("Python")
            ),
            "dgraph" to EngineDetails(
            "Dgraph",
            "https://dgraph.io/",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/dgraph.md",
            listOf("JavaScript")
            ),
            "directus" to EngineDetails(
            "Directus",
            "https://directus.io/",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/directus.md",
            listOf("TypeScript")
            ),
            "graphql_yoga" to EngineDetails(
            "GraphQL Yoga",
            "https://raw.githubusercontent.com/dotansimha/graphql-yoga",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/graphql-yoga.md",
            listOf("TypeScript")
            ),
            "lighthouse" to EngineDetails(
            "Lighthouse",
            "https://raw.githubusercontent.com/nuwave/lighthouse",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/lighthouse.md",
            listOf("PHP")
            ),
            "agoo" to EngineDetails(
            "Agoo",
            "https://raw.githubusercontent.com/ohler55/agoo",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/agoo.md",
            listOf("Ruby")
            ),
            "mercurius" to EngineDetails(
            "mercurius",
            "https://raw.githubusercontent.com/mercurius-js/mercurius",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/mercurius.md",
            listOf("JavaScript", "Node.js", "TypeScript")
            ),
            "morpheus-graphql" to EngineDetails(
            "morpheus-graphql",
            "https://raw.githubusercontent.com/morpheusgraphql/morpheus-graphql",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/morpheus-graphql.md",
            listOf("Haskell")
            ),
            "lacinia" to EngineDetails(
            "lacinia",
            "https://raw.githubusercontent.com/walmartlabs/lacinia",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/lacinia.md",
            listOf("Clojure")
            ),
            "caliban" to EngineDetails(
            "caliban",
            "https://raw.githubusercontent.com/ghostdogpr/caliban",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/caliban.md",
            listOf("Scala")
            ),
            "jaal" to EngineDetails(
            "jaal",
            "https://raw.githubusercontent.com/appointy/jaal",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/jaal",
            listOf("Golang")
            ),
            "absinthe-graphql" to EngineDetails(
            "absinthe-graphql",
            "https://raw.githubusercontent.com/absinthe-graphql/absinthe",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/absinthe-graphql.md",
            listOf("Elixir")
            ),
            "graphql-dotnet" to EngineDetails(
            "graphql-dotnet",
            "https://raw.githubusercontent.com/graphql-dotnet/graphql-dotnet",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/graphql-dotnet.md",
            listOf("C#", ".NET")
            ),
            "pg_graphql" to EngineDetails(
            "pg_graphql",
            "https://supabase.github.io/pg_graphql",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/pg_graphql.md"  ,
            listOf("Rust")
            ),
            "tailcall" to EngineDetails(
            "tailcall",
            "https://tailcall.run",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/tailcall.md",
            listOf("Rust")
            ),
            "hotchocolate" to EngineDetails(
            "hotchocolate",
            "https://chillicream.com/docs/hotchocolate/v13",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/hotchocolate.md",
            listOf("C#", ".NET")
            ),
            "inigo" to EngineDetails(
            "inigo",
            "https://inigo.io",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/inigo.md",
            listOf("Go")
            ),
            "ballerina" to EngineDetails(
            "ballerina",
            "https://raw.githubusercontent.com/ballerina-platform/module-ballerina-graphql",
            "https://raw.githubusercontent.com/nicholasaleks/graphql-threat-matrix/refs/heads/master/implementations/ballerina.md",
            listOf("Ballerina", "Java")
            ),
        )
    }
}