using Microsoft.EntityFrameworkCore;
using VH_Burguer.Contexts;
using VH_Burguer.Domains;
using VH_Burguer.Interfaces;

namespace VH_Burguer.Repositories
{
    public class ProdutoRepository : IProdutoRepository
    {
        private readonly VH_BurguerContext _context;

        public ProdutoRepository(VH_BurguerContext context)
        {
            _context = context;
        }

        public List<Produto> Listar()
        {
            List<Produto> produtos = _context.Produto.Include(produto => produto.Categoria) // busca produtos,
            // e para cada produto tras as suas categorias 
            .Include(produto => produto.Usuario) // busca produtos, e para cada produto tras os seus usuarios
            .ToList();

            return produtos;
        }

        public Produto ObterPorId(int id)
        {
            Produto? produto = _context.Produto
                .Include(produtoDb => produtoDb.Categoria)
                .Include(produtoDb => produtoDb.Usuario)

                // Procura no banco e verifica se o ID do produto no banco e igual ao id passado como parametro
                // no metodo ObterPorId
                .FirstOrDefault(produtoDb => produtoDb.ProdutoID == id);

            return produto;
        }

        public bool NomeExiste(string nome, int? produtoIdAtual = null)
        {
            // AsQueryable() -> Monta a consulta para executar passo a passo, monta a consulta na tabela produto
            // e nao executa nada no banco ainda
            var produtoConsultado = _context.Produto.AsQueryable();

            // Se o produto atual tiver valor, entao atualizamos o produto
            if (produtoIdAtual.HasValue)
            {
                produtoConsultado = produtoConsultado.Where(produto => produto.ProdutoID != produtoIdAtual.Value);
            }
            return produtoConsultado.Any(produto => produto.Nome == nome);
        }

        public byte[] ObterImagem(int id)
        {
            var produto = _context.Produto.Where(produto => produto.ProdutoID == id)
                .Select(produto => produto.Imagem)
                .FirstOrDefault();

            return produto;
        }

        public void Adicionar(Produto produto, List<int> categoriaIds)
        {
            List<Categoria> categorias = _context.Categoria
                .Where(categoria => categoriaIds.Contains(categoria.CategoriaID))
                .ToList(); // Contains -> Retorna true se houver o registro

            produto.Categoria = categorias; // adiciona as categorias incluidas ao produto

            _context.Produto.Add(produto);
            _context.SaveChanges();

        }

        public void Atualizar(Produto produto, List<int> categoriaIds)
        {
            Produto? produtoBanco = _context.Produto
                .Include(produto => produto.Categoria)
                .FirstOrDefault(produtoAux => produtoAux.ProdutoID == produto.ProdutoID);

            if (produtoBanco == null)
            {
                return;
            }

            produtoBanco.Nome = produto.Nome;
            produtoBanco.Preco = produto.Preco;
            produtoBanco.Descricao = produto.Descricao;

            if (produto.Imagem != null && produto.Imagem.Length > 0)
            {
                produtoBanco.Imagem = produto.Imagem;
            }

            if (produto.StatusProduto.HasValue)
            {
                produtoBanco.StatusProduto = produto.StatusProduto;
            }

            var categorias = _context.Categoria
                .Where(categoria => categoriaIds.Contains(categoria.CategoriaID)) // Busca todas as categorias do banco
                                                                                  // com id igual ao das que vieram da requisicao/front
                .ToList();

            produtoBanco.Categoria.Clear(); // Clear()-> Remove as ligacoes entre o produto e as categorias
            // Nao apaga as categorias, so remove o vinculo

            foreach(var categoria in categorias)
            {
                produtoBanco.Categoria.Add(categoria);
            }

            _context.SaveChanges();
        }

        public void Remover(int id)
        {
            Produto? produto = _context.Produto.FirstOrDefault(produto => produto.ProdutoID == id)
                
                if(produto == null)
                {
                        return;
                }

            _context.Produto.Remove(produto);
            _context.SaveChanges();
        }
    }
}
